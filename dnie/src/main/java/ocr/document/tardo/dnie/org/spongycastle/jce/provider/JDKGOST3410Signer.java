package org.spongycastle.jce.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.GOST3411Digest;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECGOST3410Signer;
import org.spongycastle.crypto.signers.GOST3410Signer;
import org.spongycastle.jce.interfaces.ECKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.interfaces.GOST3410Key;
import org.spongycastle.jce.provider.asymmetric.ec.ECUtil;

public class JDKGOST3410Signer extends SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private Digest digest;
    private SecureRandom random;
    private DSA signer;

    public static class ecgost3410 extends JDKGOST3410Signer {
        public ecgost3410() {
            super(new GOST3411Digest(), new ECGOST3410Signer());
        }
    }

    public static class gost3410 extends JDKGOST3410Signer {
        public gost3410() {
            super(new GOST3411Digest(), new GOST3410Signer());
        }
    }

    protected JDKGOST3410Signer(Digest digest, DSA signer) {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        CipherParameters param;
        if (publicKey instanceof ECPublicKey) {
            param = ECUtil.generatePublicKeyParameter(publicKey);
        } else if (publicKey instanceof GOST3410Key) {
            param = GOST3410Util.generatePublicKeyParameter(publicKey);
        } else {
            try {
                publicKey = JDKKeyFactory.createPublicKeyFromDERStream(publicKey.getEncoded());
                if (publicKey instanceof ECPublicKey) {
                    param = ECUtil.generatePublicKeyParameter(publicKey);
                } else {
                    throw new InvalidKeyException("can't recognise key type in DSA based signer");
                }
            } catch (Exception e) {
                throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }
        }
        this.digest.reset();
        this.signer.init(false, param);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        CipherParameters param;
        if (privateKey instanceof ECKey) {
            param = ECUtil.generatePrivateKeyParameter(privateKey);
        } else {
            param = GOST3410Util.generatePrivateKeyParameter(privateKey);
        }
        this.digest.reset();
        if (this.random != null) {
            this.signer.init(true, new ParametersWithRandom(param, this.random));
        } else {
            this.signer.init(true, param);
        }
    }

    protected void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.digest.update(b, off, len);
    }

    protected byte[] engineSign() throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            byte[] sigBytes = new byte[64];
            BigInteger[] sig = this.signer.generateSignature(hash);
            byte[] r = sig[0].toByteArray();
            byte[] s = sig[1].toByteArray();
            if (s[0] != (byte) 0) {
                System.arraycopy(s, 0, sigBytes, 32 - s.length, s.length);
            } else {
                System.arraycopy(s, 1, sigBytes, 32 - (s.length - 1), s.length - 1);
            }
            if (r[0] != (byte) 0) {
                System.arraycopy(r, 0, sigBytes, 64 - r.length, r.length);
            } else {
                System.arraycopy(r, 1, sigBytes, 64 - (r.length - 1), r.length - 1);
            }
            return sigBytes;
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            byte[] r = new byte[32];
            System.arraycopy(sigBytes, 0, new byte[32], 0, 32);
            System.arraycopy(sigBytes, 32, r, 0, 32);
            BigInteger[] sig = new BigInteger[]{new BigInteger(1, r), new BigInteger(1, s)};
            return this.signer.verifySignature(hash, sig[0], sig[1]);
        } catch (Exception e) {
            throw new SignatureException("error decoding signature bytes.");
        }
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}
