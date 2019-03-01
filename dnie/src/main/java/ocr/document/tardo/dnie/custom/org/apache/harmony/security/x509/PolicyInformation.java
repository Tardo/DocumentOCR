package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;

public class PolicyInformation {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), ASN1Any.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            return new PolicyInformation(ObjectIdentifier.toString((int[]) ((Object[]) in.content)[0]));
        }

        protected void getValues(Object object, Object[] values) {
            values[0] = ObjectIdentifier.toIntArray(((PolicyInformation) object).policyIdentifier);
        }
    };
    private byte[] encoding;
    private String policyIdentifier;

    public PolicyInformation(String policyIdentifier) {
        this.policyIdentifier = policyIdentifier;
    }

    public String getPolicyIdentifier() {
        return this.policyIdentifier;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer) {
        buffer.append("Policy Identifier [").append(this.policyIdentifier).append(']');
    }
}
