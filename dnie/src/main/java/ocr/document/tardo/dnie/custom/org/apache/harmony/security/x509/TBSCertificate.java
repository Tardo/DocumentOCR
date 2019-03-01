package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BitString;
import custom.org.apache.harmony.security.x501.Name;
import java.math.BigInteger;

public class TBSCertificate {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Explicit(0, ASN1Integer.getInstance()), ASN1Integer.getInstance(), AlgorithmIdentifier.ASN1, Name.ASN1, Validity.ASN1, Name.ASN1, SubjectPublicKeyInfo.ASN1, new ASN1Implicit(1, ASN1BitString.getInstance()), new ASN1Implicit(2, ASN1BitString.getInstance()), new ASN1Explicit(3, Extensions.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new TBSCertificate(ASN1Integer.toIntValue(values[0]), new BigInteger((byte[]) values[1]), (AlgorithmIdentifier) values[2], (Name) values[3], (Validity) values[4], (Name) values[5], (SubjectPublicKeyInfo) values[6], values[7] == null ? null : ((BitString) values[7]).toBooleanArray(), values[8] == null ? null : ((BitString) values[8]).toBooleanArray(), (Extensions) values[9], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            TBSCertificate tbs = (TBSCertificate) object;
            values[0] = ASN1Integer.fromIntValue(tbs.version);
            values[1] = tbs.serialNumber.toByteArray();
            values[2] = tbs.signature;
            values[3] = tbs.issuer;
            values[4] = tbs.validity;
            values[5] = tbs.subject;
            values[6] = tbs.subjectPublicKeyInfo;
            if (tbs.issuerUniqueID != null) {
                values[7] = new BitString(tbs.issuerUniqueID);
            }
            if (tbs.subjectUniqueID != null) {
                values[8] = new BitString(tbs.subjectUniqueID);
            }
            values[9] = tbs.extensions;
        }
    };
    byte[] encoding;
    private final Extensions extensions;
    private final Name issuer;
    private final boolean[] issuerUniqueID;
    private final BigInteger serialNumber;
    private final AlgorithmIdentifier signature;
    private final Name subject;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final boolean[] subjectUniqueID;
    private final Validity validity;
    private final int version;

    public TBSCertificate(int version, BigInteger serialNumber, AlgorithmIdentifier signature, Name issuer, Validity validity, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo) {
        this(version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, null, null, null);
    }

    public TBSCertificate(int version, BigInteger serialNumber, AlgorithmIdentifier signature, Name issuer, Validity validity, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, boolean[] issuerUniqueID, boolean[] subjectUniqueID, Extensions extensions) {
        this.version = version;
        this.serialNumber = serialNumber;
        this.signature = signature;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.issuerUniqueID = issuerUniqueID;
        this.subjectUniqueID = subjectUniqueID;
        this.extensions = extensions;
    }

    private TBSCertificate(int version, BigInteger serialNumber, AlgorithmIdentifier signature, Name issuer, Validity validity, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, boolean[] issuerUniqueID, boolean[] subjectUniqueID, Extensions extensions, byte[] encoding) {
        this(version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions);
        this.encoding = encoding;
    }

    public int getVersion() {
        return this.version;
    }

    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    public AlgorithmIdentifier getSignature() {
        return this.signature;
    }

    public Name getIssuer() {
        return this.issuer;
    }

    public Validity getValidity() {
        return this.validity;
    }

    public Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.subjectPublicKeyInfo;
    }

    public boolean[] getIssuerUniqueID() {
        return this.issuerUniqueID;
    }

    public boolean[] getSubjectUniqueID() {
        return this.subjectUniqueID;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer) {
        char c;
        buffer.append('[');
        buffer.append("\n  Version: V").append(this.version + 1);
        buffer.append("\n  Subject: ").append(this.subject.getName("RFC2253"));
        buffer.append("\n  Signature Algorithm: ");
        this.signature.dumpValue(buffer);
        buffer.append("\n  Key: ");
        buffer.append(this.subjectPublicKeyInfo.getPublicKey().toString());
        buffer.append("\n  Validity: [From: ");
        buffer.append(this.validity.getNotBefore());
        buffer.append("\n               To: ");
        buffer.append(this.validity.getNotAfter()).append(']');
        buffer.append("\n  Issuer: ");
        buffer.append(this.issuer.getName("RFC2253"));
        buffer.append("\n  Serial Number: ");
        buffer.append(this.serialNumber);
        if (this.issuerUniqueID != null) {
            buffer.append("\n  Issuer Id: ");
            for (boolean z : this.issuerUniqueID) {
                if (z) {
                    c = '1';
                } else {
                    c = '0';
                }
                buffer.append(c);
            }
        }
        if (this.subjectUniqueID != null) {
            buffer.append("\n  Subject Id: ");
            for (boolean z2 : this.subjectUniqueID) {
                if (z2) {
                    c = '1';
                } else {
                    c = '0';
                }
                buffer.append(c);
            }
        }
        if (this.extensions != null) {
            buffer.append("\n\n  Extensions: ");
            buffer.append("[\n");
            this.extensions.dumpValue(buffer, "    ");
            buffer.append("  ]");
        }
        buffer.append("\n]");
    }
}
