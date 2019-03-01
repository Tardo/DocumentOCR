package custom.org.apache.harmony.security.asn1;

import java.io.IOException;

public class ASN1Set extends ASN1TypeCollection {
    public ASN1Set(ASN1Type[] type) {
        super(17, type);
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readSet(this);
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public final void encodeContent(BerOutputStream out) {
        out.encodeSet(this);
    }

    public final void setEncodingContent(BerOutputStream out) {
        out.getSetLength(this);
    }
}
