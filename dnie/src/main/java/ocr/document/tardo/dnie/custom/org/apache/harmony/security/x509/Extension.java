package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Boolean;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import custom.org.apache.harmony.security.utils.Array;
import java.io.IOException;
import java.util.Arrays;

public class Extension {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), ASN1Boolean.getInstance(), new C02551()}) {
        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            int[] oid = (int[]) values[0];
            byte[] extnValue = (byte[]) ((Object[]) values[2])[0];
            byte[] rawExtnValue = (byte[]) ((Object[]) values[2])[1];
            ExtensionValue decodedExtValue = null;
            if (Extension.oidEquals(oid, Extension.KEY_USAGE)) {
                decodedExtValue = new KeyUsage(extnValue);
            } else if (Extension.oidEquals(oid, Extension.BASIC_CONSTRAINTS)) {
                decodedExtValue = new BasicConstraints(extnValue);
            }
            return new Extension((int[]) values[0], ((Boolean) values[1]).booleanValue(), extnValue, rawExtnValue, in.getEncoded(), decodedExtValue);
        }

        protected void getValues(Object object, Object[] values) {
            Extension ext = (Extension) object;
            values[0] = ext.extnID;
            values[1] = ext.critical ? Boolean.TRUE : Boolean.FALSE;
            values[2] = ext.extnValue;
        }
    };
    static final int[] AUTHORITY_INFO_ACCESS = new int[]{1, 3, 6, 1, 5, 5, 7, 1, 1};
    static final int[] AUTH_KEY_ID = new int[]{2, 5, 29, 35};
    static final int[] BASIC_CONSTRAINTS = new int[]{2, 5, 29, 19};
    static final int[] CERTIFICATE_ISSUER = new int[]{2, 5, 29, 29};
    static final int[] CERTIFICATE_POLICIES = new int[]{2, 5, 29, 32};
    public static final boolean CRITICAL = true;
    static final int[] CRL_DISTR_POINTS = new int[]{2, 5, 29, 31};
    static final int[] CRL_NUMBER = new int[]{2, 5, 29, 20};
    static final int[] EXTENDED_KEY_USAGE = new int[]{2, 5, 29, 37};
    static final int[] FRESHEST_CRL = new int[]{2, 5, 29, 46};
    static final int[] INHIBIT_ANY_POLICY = new int[]{2, 5, 29, 54};
    static final int[] INVALIDITY_DATE = new int[]{2, 5, 29, 24};
    static final int[] ISSUER_ALTERNATIVE_NAME = new int[]{2, 5, 29, 18};
    static final int[] ISSUING_DISTR_POINT = new int[]{2, 5, 29, 28};
    static final int[] ISSUING_DISTR_POINTS = new int[]{2, 5, 29, 28};
    static final int[] KEY_USAGE = new int[]{2, 5, 29, 15};
    static final int[] NAME_CONSTRAINTS = new int[]{2, 5, 29, 30};
    public static final boolean NON_CRITICAL = false;
    static final int[] POLICY_CONSTRAINTS = new int[]{2, 5, 29, 36};
    static final int[] POLICY_MAPPINGS = new int[]{2, 5, 29, 33};
    static final int[] PRIVATE_KEY_USAGE_PERIOD = new int[]{2, 5, 29, 16};
    static final int[] REASON_CODE = new int[]{2, 5, 29, 21};
    static final int[] SUBJECT_ALT_NAME = new int[]{2, 5, 29, 17};
    static final int[] SUBJECT_INFO_ACCESS = new int[]{1, 3, 6, 1, 5, 5, 7, 1, 11};
    static final int[] SUBJ_DIRECTORY_ATTRS = new int[]{2, 5, 29, 9};
    static final int[] SUBJ_KEY_ID = new int[]{2, 5, 29, 14};
    private final boolean critical;
    private byte[] encoding;
    private final int[] extnID;
    private String extnID_str;
    private final byte[] extnValue;
    protected ExtensionValue extnValueObject;
    private byte[] rawExtnValue;
    private boolean valueDecoded;

    /* renamed from: custom.org.apache.harmony.security.x509.Extension$1 */
    static class C02551 extends ASN1OctetString {
        C02551() {
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            return new Object[]{super.getDecodedObject(in), in.getEncoded()};
        }
    }

    public Extension(String extnID, boolean critical, ExtensionValue extnValueObject) {
        this.valueDecoded = false;
        this.extnID_str = extnID;
        this.extnID = ObjectIdentifier.toIntArray(extnID);
        this.critical = critical;
        this.extnValueObject = extnValueObject;
        this.valueDecoded = true;
        this.extnValue = extnValueObject.getEncoded();
    }

    public Extension(String extnID, boolean critical, byte[] extnValue) {
        this.valueDecoded = false;
        this.extnID_str = extnID;
        this.extnID = ObjectIdentifier.toIntArray(extnID);
        this.critical = critical;
        this.extnValue = extnValue;
    }

    public Extension(int[] extnID, boolean critical, byte[] extnValue) {
        this.valueDecoded = false;
        this.extnID = extnID;
        this.critical = critical;
        this.extnValue = extnValue;
    }

    public Extension(String extnID, byte[] extnValue) {
        this(extnID, false, extnValue);
    }

    public Extension(int[] extnID, byte[] extnValue) {
        this(extnID, false, extnValue);
    }

    private Extension(int[] extnID, boolean critical, byte[] extnValue, byte[] rawExtnValue, byte[] encoding, ExtensionValue decodedExtValue) {
        this(extnID, critical, extnValue);
        this.rawExtnValue = rawExtnValue;
        this.encoding = encoding;
        this.extnValueObject = decodedExtValue;
        this.valueDecoded = decodedExtValue != null;
    }

    public String getExtnID() {
        if (this.extnID_str == null) {
            this.extnID_str = ObjectIdentifier.toString(this.extnID);
        }
        return this.extnID_str;
    }

    public boolean getCritical() {
        return this.critical;
    }

    public byte[] getExtnValue() {
        return this.extnValue;
    }

    public byte[] getRawExtnValue() {
        if (this.rawExtnValue == null) {
            this.rawExtnValue = ASN1OctetString.getInstance().encode(this.extnValue);
        }
        return this.rawExtnValue;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public boolean equals(Object ext) {
        if (!(ext instanceof Extension)) {
            return false;
        }
        Extension extn = (Extension) ext;
        if (Arrays.equals(this.extnID, extn.extnID) && this.critical == extn.critical && Arrays.equals(this.extnValue, extn.extnValue)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return (((this.critical ? 1 : 0) + (this.extnID.hashCode() * 37)) * 37) + this.extnValue.hashCode();
    }

    public ExtensionValue getDecodedExtensionValue() throws IOException {
        if (!this.valueDecoded) {
            decodeExtensionValue();
        }
        return this.extnValueObject;
    }

    public KeyUsage getKeyUsageValue() {
        if (!this.valueDecoded) {
            try {
                decodeExtensionValue();
            } catch (IOException e) {
            }
        }
        if (this.extnValueObject instanceof KeyUsage) {
            return (KeyUsage) this.extnValueObject;
        }
        return null;
    }

    public BasicConstraints getBasicConstraintsValue() {
        if (!this.valueDecoded) {
            try {
                decodeExtensionValue();
            } catch (IOException e) {
            }
        }
        if (this.extnValueObject instanceof BasicConstraints) {
            return (BasicConstraints) this.extnValueObject;
        }
        return null;
    }

    private void decodeExtensionValue() throws IOException {
        if (!this.valueDecoded) {
            this.valueDecoded = true;
            if (oidEquals(this.extnID, SUBJ_KEY_ID)) {
                this.extnValueObject = SubjectKeyIdentifier.decode(this.extnValue);
            } else if (oidEquals(this.extnID, KEY_USAGE)) {
                this.extnValueObject = new KeyUsage(this.extnValue);
            } else if (oidEquals(this.extnID, SUBJECT_ALT_NAME)) {
                this.extnValueObject = new AlternativeName(true, this.extnValue);
            } else if (oidEquals(this.extnID, ISSUER_ALTERNATIVE_NAME)) {
                this.extnValueObject = new AlternativeName(true, this.extnValue);
            } else if (oidEquals(this.extnID, BASIC_CONSTRAINTS)) {
                this.extnValueObject = new BasicConstraints(this.extnValue);
            } else if (oidEquals(this.extnID, NAME_CONSTRAINTS)) {
                this.extnValueObject = NameConstraints.decode(this.extnValue);
            } else if (oidEquals(this.extnID, CERTIFICATE_POLICIES)) {
                this.extnValueObject = CertificatePolicies.decode(this.extnValue);
            } else if (oidEquals(this.extnID, AUTH_KEY_ID)) {
                this.extnValueObject = AuthorityKeyIdentifier.decode(this.extnValue);
            } else if (oidEquals(this.extnID, POLICY_CONSTRAINTS)) {
                this.extnValueObject = new PolicyConstraints(this.extnValue);
            } else if (oidEquals(this.extnID, EXTENDED_KEY_USAGE)) {
                this.extnValueObject = new ExtendedKeyUsage(this.extnValue);
            } else if (oidEquals(this.extnID, INHIBIT_ANY_POLICY)) {
                this.extnValueObject = new InhibitAnyPolicy(this.extnValue);
            } else if (oidEquals(this.extnID, CERTIFICATE_ISSUER)) {
                this.extnValueObject = new CertificateIssuer(this.extnValue);
            } else if (oidEquals(this.extnID, CRL_DISTR_POINTS)) {
                this.extnValueObject = CRLDistributionPoints.decode(this.extnValue);
            } else if (oidEquals(this.extnID, CERTIFICATE_ISSUER)) {
                this.extnValueObject = new ReasonCode(this.extnValue);
            } else if (oidEquals(this.extnID, INVALIDITY_DATE)) {
                this.extnValueObject = new InvalidityDate(this.extnValue);
            } else if (oidEquals(this.extnID, REASON_CODE)) {
                this.extnValueObject = new ReasonCode(this.extnValue);
            } else if (oidEquals(this.extnID, CRL_NUMBER)) {
                this.extnValueObject = new CRLNumber(this.extnValue);
            } else if (oidEquals(this.extnID, ISSUING_DISTR_POINTS)) {
                this.extnValueObject = IssuingDistributionPoint.decode(this.extnValue);
            } else if (oidEquals(this.extnID, AUTHORITY_INFO_ACCESS)) {
                this.extnValueObject = InfoAccessSyntax.decode(this.extnValue);
            } else if (oidEquals(this.extnID, SUBJECT_INFO_ACCESS)) {
                this.extnValueObject = InfoAccessSyntax.decode(this.extnValue);
            }
        }
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append("OID: ").append(getExtnID()).append(", Critical: ").append(this.critical).append('\n');
        if (!this.valueDecoded) {
            try {
                decodeExtensionValue();
            } catch (IOException e) {
            }
        }
        if (this.extnValueObject != null) {
            this.extnValueObject.dumpValue(buffer, prefix);
            return;
        }
        buffer.append(prefix);
        if (oidEquals(this.extnID, SUBJ_DIRECTORY_ATTRS)) {
            buffer.append("Subject Directory Attributes Extension");
        } else if (oidEquals(this.extnID, SUBJ_KEY_ID)) {
            buffer.append("Subject Key Identifier Extension");
        } else if (oidEquals(this.extnID, KEY_USAGE)) {
            buffer.append("Key Usage Extension");
        } else if (oidEquals(this.extnID, PRIVATE_KEY_USAGE_PERIOD)) {
            buffer.append("Private Key Usage Period Extension");
        } else if (oidEquals(this.extnID, SUBJECT_ALT_NAME)) {
            buffer.append("Subject Alternative Name Extension");
        } else if (oidEquals(this.extnID, ISSUER_ALTERNATIVE_NAME)) {
            buffer.append("Issuer Alternative Name Extension");
        } else if (oidEquals(this.extnID, BASIC_CONSTRAINTS)) {
            buffer.append("Basic Constraints Extension");
        } else if (oidEquals(this.extnID, NAME_CONSTRAINTS)) {
            buffer.append("Name Constraints Extension");
        } else if (oidEquals(this.extnID, CRL_DISTR_POINTS)) {
            buffer.append("CRL Distribution Points Extension");
        } else if (oidEquals(this.extnID, CERTIFICATE_POLICIES)) {
            buffer.append("Certificate Policies Extension");
        } else if (oidEquals(this.extnID, POLICY_MAPPINGS)) {
            buffer.append("Policy Mappings Extension");
        } else if (oidEquals(this.extnID, AUTH_KEY_ID)) {
            buffer.append("Authority Key Identifier Extension");
        } else if (oidEquals(this.extnID, POLICY_CONSTRAINTS)) {
            buffer.append("Policy Constraints Extension");
        } else if (oidEquals(this.extnID, EXTENDED_KEY_USAGE)) {
            buffer.append("Extended Key Usage Extension");
        } else if (oidEquals(this.extnID, INHIBIT_ANY_POLICY)) {
            buffer.append("Inhibit Any-Policy Extension");
        } else if (oidEquals(this.extnID, AUTHORITY_INFO_ACCESS)) {
            buffer.append("Authority Information Access Extension");
        } else if (oidEquals(this.extnID, SUBJECT_INFO_ACCESS)) {
            buffer.append("Subject Information Access Extension");
        } else if (oidEquals(this.extnID, INVALIDITY_DATE)) {
            buffer.append("Invalidity Date Extension");
        } else if (oidEquals(this.extnID, CRL_NUMBER)) {
            buffer.append("CRL Number Extension");
        } else if (oidEquals(this.extnID, REASON_CODE)) {
            buffer.append("Reason Code Extension");
        } else {
            buffer.append("Unknown Extension");
        }
        buffer.append('\n').append(prefix).append("Unparsed Extension Value:\n");
        buffer.append(Array.toString(this.extnValue, prefix));
    }

    private static boolean oidEquals(int[] oid1, int[] oid2) {
        int length = oid1.length;
        if (length != oid2.length) {
            return false;
        }
        while (length > 0) {
            length--;
            if (oid1[length] != oid2[length]) {
                return false;
            }
        }
        return true;
    }
}
