package custom.org.apache.harmony.security.asn1;

import java.io.IOException;

public class ASN1Sequence extends ASN1TypeCollection {
    public ASN1Sequence(ASN1Type[] type) {
        super(16, type);
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readSequence(this);
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public final void encodeContent(BerOutputStream out) {
        out.encodeSequence(this);
    }

    public final void setEncodingContent(BerOutputStream out) {
        out.getSequenceLength(this);
    }
}
