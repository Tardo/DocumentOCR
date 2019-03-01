package custom.org.apache.harmony.security.pkcs7;

import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.AttributeTypeAndValue;
import java.util.List;

class AuthenticatedAttributes {
    public static final ASN1SetOf ASN1 = new ASN1SetOf(AttributeTypeAndValue.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new AuthenticatedAttributes(in.getEncoded(), (List) in.content);
        }
    };
    private List authenticatedAttributes;
    private byte[] encoding;

    public AuthenticatedAttributes(byte[] encoding, List authenticatedAttributes) {
        this.encoding = encoding;
        this.authenticatedAttributes = authenticatedAttributes;
    }

    public List getAttributes() {
        return this.authenticatedAttributes;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
