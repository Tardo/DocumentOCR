package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BitString;
import custom.org.apache.harmony.security.utils.Array;

public class Certificate {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{TBSCertificate.ASN1, AlgorithmIdentifier.ASN1, ASN1BitString.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new Certificate((TBSCertificate) values[0], (AlgorithmIdentifier) values[1], ((BitString) values[2]).bytes, in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            Certificate cert = (Certificate) object;
            values[0] = cert.tbsCertificate;
            values[1] = cert.signatureAlgorithm;
            values[2] = new BitString(cert.signatureValue, 0);
        }
    };
    private byte[] encoding;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final byte[] signatureValue;
    private final TBSCertificate tbsCertificate;

    public Certificate(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgorithm, byte[] signatureValue) {
        this.tbsCertificate = tbsCertificate;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = new byte[signatureValue.length];
        System.arraycopy(signatureValue, 0, this.signatureValue, 0, signatureValue.length);
    }

    private Certificate(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgorithm, byte[] signatureValue, byte[] encoding) {
        this(tbsCertificate, signatureAlgorithm, signatureValue);
        this.encoding = encoding;
    }

    public TBSCertificate getTbsCertificate() {
        return this.tbsCertificate;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public byte[] getSignatureValue() {
        byte[] result = new byte[this.signatureValue.length];
        System.arraycopy(this.signatureValue, 0, result, 0, this.signatureValue.length);
        return result;
    }

    public String toString() {
        StringBuffer buffer = new StringBuffer();
        buffer.append("X.509 Certificate:\n[\n");
        this.tbsCertificate.dumpValue(buffer);
        buffer.append("\n  Algorithm: [");
        this.signatureAlgorithm.dumpValue(buffer);
        buffer.append(']');
        buffer.append("\n  Signature Value:\n");
        buffer.append(Array.toString(this.signatureValue, ""));
        buffer.append(']');
        return buffer.toString();
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
