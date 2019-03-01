package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.agreement.DHBasicAgreement;
import org.spongycastle.crypto.agreement.ECDHBasicAgreement;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.engines.IESEngine;
import org.spongycastle.crypto.generators.KDF2BytesGenerator;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.IESParameters;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.interfaces.IESKey;
import org.spongycastle.jce.provider.asymmetric.ec.ECUtil;
import org.spongycastle.jce.spec.IESParameterSpec;

public class JCEIESCipher extends WrapCipherSpi {
    private Class[] availableSpecs = new Class[]{IESParameterSpec.class};
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private IESEngine cipher;
    private AlgorithmParameters engineParam = null;
    private IESParameterSpec engineParams = null;
    private int state = -1;

    public static class BrokenECIES extends JCEIESCipher {
        public BrokenECIES() {
            super(new IESEngine(new ECDHBasicAgreement(), new BrokenKDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
        }
    }

    public static class BrokenIES extends JCEIESCipher {
        public BrokenIES() {
            super(new IESEngine(new DHBasicAgreement(), new BrokenKDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
        }
    }

    public static class ECIES extends JCEIESCipher {
        public ECIES() {
            super(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
        }
    }

    public static class IES extends JCEIESCipher {
        public IES() {
            super(new IESEngine(new DHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
        }
    }

    public JCEIESCipher(IESEngine engine) {
        this.cipher = engine;
    }

    protected int engineGetBlockSize() {
        return 0;
    }

    protected byte[] engineGetIV() {
        return null;
    }

    protected int engineGetKeySize(Key key) {
        if (key instanceof IESKey) {
            IESKey ieKey = (IESKey) key;
            if (ieKey.getPrivate() instanceof DHPrivateKey) {
                return ((DHPrivateKey) ieKey.getPrivate()).getX().bitLength();
            }
            if (ieKey.getPrivate() instanceof ECPrivateKey) {
                return ((ECPrivateKey) ieKey.getPrivate()).getD().bitLength();
            }
            throw new IllegalArgumentException("not an IE key!");
        }
        throw new IllegalArgumentException("must be passed IE key");
    }

    protected int engineGetOutputSize(int inputLen) {
        if (this.state == 1 || this.state == 3) {
            return (this.buffer.size() + inputLen) + 20;
        }
        if (this.state == 2 || this.state == 4) {
            return (this.buffer.size() + inputLen) - 20;
        }
        throw new IllegalStateException("cipher not initialised");
    }

    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParam == null && this.engineParams != null) {
            try {
                this.engineParam = AlgorithmParameters.getInstance("IES", BouncyCastleProvider.PROVIDER_NAME);
                this.engineParam.init(this.engineParams);
            } catch (Exception e) {
                throw new RuntimeException(e.toString());
            }
        }
        return this.engineParam;
    }

    protected void engineSetMode(String mode) {
        throw new IllegalArgumentException("can't support mode " + mode);
    }

    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException(padding + " unavailable with RSA.");
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key instanceof IESKey) {
            CipherParameters pubKey;
            CipherParameters privKey;
            if (params == null && (opmode == 1 || opmode == 3)) {
                byte[] d = new byte[16];
                byte[] e = new byte[16];
                if (random == null) {
                    random = new SecureRandom();
                }
                random.nextBytes(d);
                random.nextBytes(e);
                params = new IESParameterSpec(d, e, 128);
            } else if (!(params instanceof IESParameterSpec)) {
                throw new InvalidAlgorithmParameterException("must be passed IES parameters");
            }
            IESKey ieKey = (IESKey) key;
            if (ieKey.getPublic() instanceof ECPublicKey) {
                pubKey = ECUtil.generatePublicKeyParameter(ieKey.getPublic());
                privKey = ECUtil.generatePrivateKeyParameter(ieKey.getPrivate());
            } else {
                pubKey = DHUtil.generatePublicKeyParameter(ieKey.getPublic());
                privKey = DHUtil.generatePrivateKeyParameter(ieKey.getPrivate());
            }
            this.engineParams = (IESParameterSpec) params;
            IESParameters p = new IESParameters(this.engineParams.getDerivationV(), this.engineParams.getEncodingV(), this.engineParams.getMacKeySize());
            this.state = opmode;
            this.buffer.reset();
            switch (opmode) {
                case 1:
                case 3:
                    this.cipher.init(true, privKey, pubKey, p);
                    return;
                case 2:
                case 4:
                    this.cipher.init(false, privKey, pubKey, p);
                    return;
                default:
                    System.out.println("eeek!");
                    return;
            }
        }
        throw new InvalidKeyException("must be passed IES key");
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            int i = 0;
            while (i != this.availableSpecs.length) {
                try {
                    paramSpec = params.getParameterSpec(this.availableSpecs[i]);
                    break;
                } catch (Exception e) {
                    i++;
                }
            }
            if (paramSpec == null) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }
        this.engineParam = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (opmode == 1 || opmode == 3) {
            try {
                engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
                return;
            } catch (InvalidAlgorithmParameterException e) {
            }
        }
        throw new IllegalArgumentException("can't handle null parameter spec in IES");
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        this.buffer.write(input, inputOffset, inputLen);
        return null;
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        this.buffer.write(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (inputLen != 0) {
            this.buffer.write(input, inputOffset, inputLen);
        }
        try {
            byte[] buf = this.buffer.toByteArray();
            this.buffer.reset();
            return this.cipher.processBlock(buf, 0, buf.length);
        } catch (InvalidCipherTextException e) {
            throw new BadPaddingException(e.getMessage());
        }
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws IllegalBlockSizeException, BadPaddingException {
        if (inputLen != 0) {
            this.buffer.write(input, inputOffset, inputLen);
        }
        try {
            byte[] buf = this.buffer.toByteArray();
            this.buffer.reset();
            buf = this.cipher.processBlock(buf, 0, buf.length);
            System.arraycopy(buf, 0, output, outputOffset, buf.length);
            return buf.length;
        } catch (InvalidCipherTextException e) {
            throw new BadPaddingException(e.getMessage());
        }
    }
}
