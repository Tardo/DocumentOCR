package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BitString;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class SubjectPublicKeyInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{AlgorithmIdentifier.ASN1, ASN1BitString.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new SubjectPublicKeyInfo((AlgorithmIdentifier) values[0], ((BitString) values[1]).bytes, ((BitString) values[1]).unusedBits, in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) object;
            values[0] = spki.algorithmID;
            values[1] = new BitString(spki.subjectPublicKey, spki.unusedBits);
        }
    };
    private AlgorithmIdentifier algorithmID;
    private byte[] encoding;
    private PublicKey publicKey;
    private byte[] subjectPublicKey;
    private int unusedBits;

    public SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] subjectPublicKey) {
        this(algID, subjectPublicKey, 0);
    }

    public SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] subjectPublicKey, int unused) {
        this(algID, subjectPublicKey, 0, null);
    }

    private SubjectPublicKeyInfo(AlgorithmIdentifier algID, byte[] subjectPublicKey, int unused, byte[] encoding) {
        this.algorithmID = algID;
        this.subjectPublicKey = subjectPublicKey;
        this.unusedBits = unused;
        this.encoding = encoding;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.algorithmID;
    }

    public byte[] getSubjectPublicKey() {
        return this.subjectPublicKey;
    }

    public int getUnusedBits() {
        return this.unusedBits;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public PublicKey getPublicKey() {
        if (this.publicKey == null) {
            String alg_oid = this.algorithmID.getAlgorithm();
            try {
                String alg = AlgNameMapper.map2AlgName(alg_oid);
                if (alg == null) {
                    alg = alg_oid;
                }
                this.publicKey = KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(getEncoded()));
            } catch (InvalidKeySpecException e) {
            } catch (NoSuchAlgorithmException e2) {
            }
            if (this.publicKey == null) {
                this.publicKey = new X509PublicKey(alg_oid, getEncoded(), this.subjectPublicKey);
            }
        }
        return this.publicKey;
    }
}
