package custom.org.apache.harmony.security.pkcs10;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.AttributeTypeAndValue;
import custom.org.apache.harmony.security.x501.Name;
import custom.org.apache.harmony.security.x509.SubjectPublicKeyInfo;
import java.util.List;

public class CertificationRequestInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), Name.ASN1, SubjectPublicKeyInfo.ASN1, new ASN1Implicit(0, new ASN1SetOf(AttributeTypeAndValue.ASN1))}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new CertificationRequestInfo(ASN1Integer.toIntValue(values[0]), (Name) values[1], (SubjectPublicKeyInfo) values[2], (List) values[3], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            CertificationRequestInfo certReqInfo = (CertificationRequestInfo) object;
            values[0] = ASN1Integer.fromIntValue(certReqInfo.version);
            values[1] = certReqInfo.subject;
            values[2] = certReqInfo.subjectPublicKeyInfo;
            values[3] = certReqInfo.attributes;
        }
    };
    private List attributes;
    private byte[] encoding;
    private Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private int version;

    public CertificationRequestInfo(int version, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, List attributes) {
        this.version = version;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.attributes = attributes;
    }

    private CertificationRequestInfo(int version, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, List attributes, byte[] encoding) {
        this(version, subject, subjectPublicKeyInfo, attributes);
        this.encoding = encoding;
    }

    public List getAttributes() {
        return this.attributes;
    }

    public Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.subjectPublicKeyInfo;
    }

    public int getVersion() {
        return this.version;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("-- CertificationRequestInfo:");
        res.append("\n version: ");
        res.append(this.version);
        res.append("\n subject: ");
        res.append(this.subject.getName("CANONICAL"));
        res.append("\n subjectPublicKeyInfo: ");
        res.append("\n\t algorithm: " + this.subjectPublicKeyInfo.getAlgorithmIdentifier().getAlgorithm());
        res.append("\n\t public key: " + this.subjectPublicKeyInfo.getPublicKey());
        res.append("\n attributes: ");
        if (this.attributes != null) {
            res.append(this.attributes.toString());
        } else {
            res.append("none");
        }
        res.append("\n-- CertificationRequestInfo End\n");
        return res.toString();
    }
}
