package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;

public final class ASN1Explicit extends ASN1Constructured {
    public final ASN1Type type;

    public ASN1Explicit(int tagNumber, ASN1Type type) {
        this(128, tagNumber, type);
    }

    public ASN1Explicit(int tagClass, int tagNumber, ASN1Type type) {
        super(tagClass, tagNumber);
        this.type = type;
    }

    public Object decode(BerInputStream in) throws IOException {
        if (this.constrId != in.tag) {
            throw new ASN1Exception(Messages.getString("security.13F", new Object[]{Integer.valueOf(in.tagOffset), Integer.toHexString(this.constrId), Integer.toHexString(in.tag)}));
        }
        in.next();
        in.content = this.type.decode(in);
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeExplicit(this);
    }

    public void setEncodingContent(BerOutputStream out) {
        out.getExplicitLength(this);
    }

    public String toString() {
        return super.toString() + " for type " + this.type;
    }
}
