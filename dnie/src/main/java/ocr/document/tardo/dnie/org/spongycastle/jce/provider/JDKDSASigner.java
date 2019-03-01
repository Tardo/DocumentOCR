package org.spongycastle.jce.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAKey;
import java.security.spec.AlgorithmParameterSpec;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.DSASigner;
import org.spongycastle.jce.interfaces.GOST3410Key;

public class JDKDSASigner extends SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private Digest digest;
    private SecureRandom random;
    private DSA signer;

    public static class dsa224 extends JDKDSASigner {
        public dsa224() {
            super(new SHA224Digest(), new DSASigner());
        }
    }

    public static class dsa256 extends JDKDSASigner {
        public dsa256() {
            super(new SHA256Digest(), new DSASigner());
        }
    }

    public static class dsa384 extends JDKDSASigner {
        public dsa384() {
            super(new SHA384Digest(), new DSASigner());
        }
    }

    public static class dsa512 extends JDKDSASigner {
        public dsa512() {
            super(new SHA512Digest(), new DSASigner());
        }
    }

    public static class noneDSA extends JDKDSASigner {
        public noneDSA() {
            super(new NullDigest(), new DSASigner());
        }
    }

    public static class stdDSA extends JDKDSASigner {
        public stdDSA() {
            super(new SHA1Digest(), new DSASigner());
        }
    }

    protected JDKDSASigner(Digest digest, DSA signer) {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        CipherParameters param;
        if (publicKey instanceof GOST3410Key) {
            param = GOST3410Util.generatePublicKeyParameter(publicKey);
        } else if (publicKey instanceof DSAKey) {
            param = DSAUtil.generatePublicKeyParameter(publicKey);
        } else {
            try {
                publicKey = JDKKeyFactory.createPublicKeyFromDERStream(publicKey.getEncoded());
                if (publicKey instanceof DSAKey) {
                    param = DSAUtil.generatePublicKeyParameter(publicKey);
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
        if (privateKey instanceof GOST3410Key) {
            param = GOST3410Util.generatePrivateKeyParameter(privateKey);
        } else {
            param = DSAUtil.generatePrivateKeyParameter(privateKey);
        }
        if (this.random != null) {
            param = new ParametersWithRandom(param, this.random);
        }
        this.digest.reset();
        this.signer.init(true, param);
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
            BigInteger[] sig = this.signer.generateSignature(hash);
            return derEncode(sig[0], sig[1]);
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            BigInteger[] sig = derDecode(sigBytes);
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

    private byte[] derEncode(BigInteger r, BigInteger s) throws IOException {
        return new DERSequence(new DERInteger[]{new DERInteger(r), new DERInteger(s)}).getEncoded("DER");
    }

    private BigInteger[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence) ASN1Object.fromByteArray(encoding);
        return new BigInteger[]{((DERInteger) s.getObjectAt(0)).getValue(), ((DERInteger) s.getObjectAt(1)).getValue()};
    }
}
