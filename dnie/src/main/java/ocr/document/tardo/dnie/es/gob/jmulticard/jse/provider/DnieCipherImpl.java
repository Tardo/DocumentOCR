package es.gob.jmulticard.jse.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class DnieCipherImpl extends CipherSpi {
    private static final int DNIE_PRIVATE_KEY_LENGTH = 2048;
    private static final String PAD_PKCS1 = "PKCS1Padding";
    private int bufOfs;
    private byte[] buffer;
    private Cipher cipher;
    private String encodingType;
    private int paddingLength = 0;
    private DniePrivateKey privateKey;
    private Signature signature;

    public static final class RSA extends DnieCipherImpl {
        public RSA() {
            super("RSA");
        }
    }

    public static final class RSAPKCS1 extends DnieCipherImpl {
        public RSAPKCS1() {
            super("RSA/ECB/PKCS1Padding");
        }
    }

    public DnieCipherImpl(String encoding) {
        this.encodingType = encoding;
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("ECB")) {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode);
        }
    }

    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase(PAD_PKCS1)) {
            throw new NoSuchPaddingException("Padding " + padding + " not supported");
        }
    }

    protected int engineGetBlockSize() {
        return 0;
    }

    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    protected byte[] engineGetIV() {
        return null;
    }

    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        init(opmode, key);
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not supported");
        }
        init(opmode, key);
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not supported");
        }
        init(opmode, key);
    }

    private void init(int opmode, Key key) throws InvalidKeyException {
        if ((key instanceof DniePrivateKey) || (key instanceof MrtdPrivateKey)) {
            switch (opmode) {
                case 1:
                case 3:
                    this.paddingLength = 0;
                    this.privateKey = (DniePrivateKey) key;
                    this.bufOfs = 0;
                    this.buffer = new byte[256];
                    try {
                        this.signature = Signature.getInstance("NONEwithRSA", "DNIeJCAProvider");
                        this.signature.initSign(this.privateKey);
                        return;
                    } catch (NoSuchAlgorithmException e) {
                        throw new ProviderException(e.getMessage());
                    } catch (NoSuchProviderException e2) {
                        throw new ProviderException(e2.getMessage());
                    }
                default:
                    throw new InvalidKeyException("Unsupported or Unknown mode: " + opmode);
            }
        }
        Provider[] providers = Security.getProviders();
        int i = 0;
        while (i < providers.length) {
            Provider prov = providers[i];
            if (prov instanceof DnieProvider) {
                i++;
            } else {
                try {
                    this.cipher = Cipher.getInstance(this.encodingType, prov);
                    this.cipher.init(opmode, key);
                    return;
                } catch (NoSuchAlgorithmException e3) {
                    this.cipher = null;
                } catch (NoSuchPaddingException e4) {
                    this.cipher = null;
                }
            }
        }
        throw new InvalidKeyException("Unsupported key type " + key);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        update(input, inputOffset, inputLen);
        if (this.cipher != null) {
            return this.cipher.update(input, inputOffset, inputLen);
        }
        return new byte[0];
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if (this.cipher != null) {
            return this.cipher.update(input, inputOffset, inputLen, output, outputOffset);
        }
        update(input, inputOffset, inputLen);
        return 0;
    }

    private void update(byte[] in, int inOfs, int inLen) {
        if (inLen != 0 && in != null) {
            if (this.bufOfs + inLen > this.buffer.length - this.paddingLength) {
                this.bufOfs = this.buffer.length + 1;
                return;
            }
            System.arraycopy(in, inOfs, this.buffer, this.bufOfs, inLen);
            this.bufOfs += inLen;
        }
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (this.cipher != null) {
            byte[] ret = this.cipher.doFinal(input, inputOffset, inputLen);
            this.cipher = null;
            return ret;
        }
        if (!(input == null || new byte[0].equals(input))) {
            update(input, inputOffset, inputLen);
        }
        return doFinal();
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (this.cipher != null) {
            int ret = this.cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            this.cipher = null;
            return ret;
        }
        update(input, inputOffset, inputLen);
        byte[] ret2 = doFinal();
        if (ret2.length + outputOffset >= output.length) {
            return ret2.length;
        }
        throw new ShortBufferException("Got " + output.length + " bytes, needed " + (ret2.length + outputOffset) + " bytes.");
    }

    private byte[] doFinal() throws BadPaddingException, IllegalBlockSizeException {
        if (this.bufOfs > this.buffer.length) {
            throw new IllegalBlockSizeException("Data must not be longer than " + (this.buffer.length - this.paddingLength) + " bytes");
        }
        try {
            byte[] data = new byte[this.bufOfs];
            System.arraycopy(this.buffer, 0, data, 0, this.bufOfs);
            this.signature.update(data);
            byte[] firma = this.signature.sign();
            this.bufOfs = 0;
            return firma;
        } catch (SignatureException e) {
            throw new ProviderException(e.getMessage());
        } catch (Throwable th) {
            this.bufOfs = 0;
        }
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
        if (this.cipher != null) {
            return this.cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
        }
        throw new UnsupportedOperationException();
    }

    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (this.cipher != null) {
            return this.cipher.wrap(key);
        }
        throw new UnsupportedOperationException();
    }
}
