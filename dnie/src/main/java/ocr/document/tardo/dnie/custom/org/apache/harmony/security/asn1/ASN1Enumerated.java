package custom.org.apache.harmony.security.asn1;

import java.io.IOException;

public class ASN1Enumerated extends ASN1Primitive {
    private static final ASN1Enumerated ASN1 = new ASN1Enumerated();

    public ASN1Enumerated() {
        super(10);
    }

    public static ASN1Enumerated getInstance() {
        return ASN1;
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readEnumerated();
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        byte[] bytesEncoded = new byte[in.length];
        System.arraycopy(in.buffer, in.contentOffset, bytesEncoded, 0, in.length);
        return bytesEncoded;
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeInteger();
    }

    public void setEncodingContent(BerOutputStream out) {
        out.length = ((byte[]) out.content).length;
    }
}
