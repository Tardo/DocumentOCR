package org.spongycastle.jce.provider.asymmetric.ec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.ECNRSigner;
import org.spongycastle.jce.interfaces.ECKey;
import org.spongycastle.jce.provider.DSABase;
import org.spongycastle.jce.provider.DSAEncoder;
import org.spongycastle.jce.provider.JDKKeyFactory;

public class Signature extends DSABase {

    private static class CVCDSAEncoder implements DSAEncoder {
        private CVCDSAEncoder() {
        }

        public byte[] encode(BigInteger r, BigInteger s) throws IOException {
            byte[] res;
            byte[] first = makeUnsigned(r);
            byte[] second = makeUnsigned(s);
            if (first.length > second.length) {
                res = new byte[(first.length * 2)];
            } else {
                res = new byte[(second.length * 2)];
            }
            System.arraycopy(first, 0, res, (res.length / 2) - first.length, first.length);
            System.arraycopy(second, 0, res, res.length - second.length, second.length);
            return res;
        }

        private byte[] makeUnsigned(BigInteger val) {
            byte[] res = val.toByteArray();
            if (res[0] != (byte) 0) {
                return res;
            }
            byte[] tmp = new byte[(res.length - 1)];
            System.arraycopy(res, 1, tmp, 0, tmp.length);
            return tmp;
        }

        public BigInteger[] decode(byte[] encoding) throws IOException {
            BigInteger[] sig = new BigInteger[2];
            byte[] first = new byte[(encoding.length / 2)];
            byte[] second = new byte[(encoding.length / 2)];
            System.arraycopy(encoding, 0, first, 0, first.length);
            System.arraycopy(encoding, first.length, second, 0, second.length);
            sig[0] = new BigInteger(1, first);
            sig[1] = new BigInteger(1, second);
            return sig;
        }
    }

    private static class StdDSAEncoder implements DSAEncoder {
        private StdDSAEncoder() {
        }

        public byte[] encode(BigInteger r, BigInteger s) throws IOException {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERInteger(r));
            v.add(new DERInteger(s));
            return new DERSequence(v).getEncoded("DER");
        }

        public BigInteger[] decode(byte[] encoding) throws IOException {
            ASN1Sequence s = (ASN1Sequence) ASN1Object.fromByteArray(encoding);
            return new BigInteger[]{((DERInteger) s.getObjectAt(0)).getValue(), ((DERInteger) s.getObjectAt(1)).getValue()};
        }
    }

    public static class ecCVCDSA224 extends Signature {
        public ecCVCDSA224() {
            super(new SHA224Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    public static class ecCVCDSA256 extends Signature {
        public ecCVCDSA256() {
            super(new SHA256Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    public static class ecCVCDSA extends Signature {
        public ecCVCDSA() {
            super(new SHA1Digest(), new ECDSASigner(), new CVCDSAEncoder());
        }
    }

    public static class ecDSA224 extends Signature {
        public ecDSA224() {
            super(new SHA224Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSA256 extends Signature {
        public ecDSA256() {
            super(new SHA256Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSA384 extends Signature {
        public ecDSA384() {
            super(new SHA384Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSA512 extends Signature {
        public ecDSA512() {
            super(new SHA512Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSA extends Signature {
        public ecDSA() {
            super(new SHA1Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSARipeMD160 extends Signature {
        public ecDSARipeMD160() {
            super(new RIPEMD160Digest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecDSAnone extends Signature {
        public ecDSAnone() {
            super(new NullDigest(), new ECDSASigner(), new StdDSAEncoder());
        }
    }

    public static class ecNR224 extends Signature {
        public ecNR224() {
            super(new SHA224Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    public static class ecNR256 extends Signature {
        public ecNR256() {
            super(new SHA256Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    public static class ecNR384 extends Signature {
        public ecNR384() {
            super(new SHA384Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    public static class ecNR512 extends Signature {
        public ecNR512() {
            super(new SHA512Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    public static class ecNR extends Signature {
        public ecNR() {
            super(new SHA1Digest(), new ECNRSigner(), new StdDSAEncoder());
        }
    }

    Signature(Digest digest, DSA signer, DSAEncoder encoder) {
        super(digest, signer, encoder);
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        CipherParameters param;
        if (publicKey instanceof ECPublicKey) {
            param = ECUtil.generatePublicKeyParameter(publicKey);
        } else {
            try {
                publicKey = JDKKeyFactory.createPublicKeyFromDERStream(publicKey.getEncoded());
                if (publicKey instanceof ECPublicKey) {
                    param = ECUtil.generatePublicKeyParameter(publicKey);
                } else {
                    throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
                }
            } catch (Exception e) {
                throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
            }
        }
        this.digest.reset();
        this.signer.init(false, param);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (privateKey instanceof ECKey) {
            CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);
            this.digest.reset();
            if (random != null) {
                this.signer.init(true, new ParametersWithRandom(param, random));
                return;
            } else {
                this.signer.init(true, param);
                return;
            }
        }
        throw new InvalidKeyException("can't recognise key type in ECDSA based signer");
    }
}
