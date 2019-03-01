package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;

public class AccessDescription {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), GeneralName.ASN1}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new AccessDescription(ObjectIdentifier.toString((int[]) values[0]), (GeneralName) values[1], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            AccessDescription ad = (AccessDescription) object;
            values[0] = ObjectIdentifier.toIntArray(ad.accessMethod);
            values[1] = ad.accessLocation;
        }
    };
    private final GeneralName accessLocation;
    private final String accessMethod;
    private byte[] encoding;

    public AccessDescription(String accessMethod, GeneralName accessLocation) {
        this.accessMethod = accessMethod;
        this.accessLocation = accessLocation;
    }

    private AccessDescription(String accessMethod, GeneralName accessLocation, byte[] encoding) {
        this.accessMethod = accessMethod;
        this.accessLocation = accessLocation;
        this.encoding = encoding;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("\n-- AccessDescription:");
        res.append("\naccessMethod:  ");
        res.append(this.accessMethod);
        res.append("\naccessLocation:  ");
        res.append(this.accessLocation);
        res.append("\n-- AccessDescription END\n");
        return res.toString();
    }

    public GeneralName getAccessLocation() {
        return this.accessLocation;
    }

    public String getAccessMethod() {
        return this.accessMethod;
    }
}
