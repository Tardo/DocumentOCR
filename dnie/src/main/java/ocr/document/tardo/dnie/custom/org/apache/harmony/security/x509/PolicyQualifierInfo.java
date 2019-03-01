package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;

public class PolicyQualifierInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), ASN1Any.getInstance()}) {
    };
}
