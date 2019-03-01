package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;

public class OtherName {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), new ASN1Explicit(0, ASN1Any.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new OtherName(ObjectIdentifier.toString((int[]) values[0]), (byte[]) values[1], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            OtherName on = (OtherName) object;
            values[0] = ObjectIdentifier.toIntArray(on.typeID);
            values[1] = on.value;
        }
    };
    private byte[] encoding;
    private String typeID;
    private byte[] value;

    public OtherName(String typeID, byte[] value) {
        this(typeID, value, null);
    }

    private OtherName(String typeID, byte[] value, byte[] encoding) {
        this.typeID = typeID;
        this.value = value;
        this.encoding = encoding;
    }

    public String getTypeID() {
        return this.typeID;
    }

    public byte[] getValue() {
        return this.value;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
