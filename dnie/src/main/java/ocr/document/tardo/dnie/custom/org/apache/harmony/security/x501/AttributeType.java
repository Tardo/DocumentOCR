package custom.org.apache.harmony.security.x501;

import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;

public class AttributeType {
    public final ObjectIdentifier oid;
    public final ASN1Type type;

    public AttributeType(ObjectIdentifier oid, ASN1Type type) {
        this.oid = oid;
        this.type = type;
    }
}
