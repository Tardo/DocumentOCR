package custom.org.apache.harmony.security.asn1;

import java.io.IOException;

public class ASN1Any extends ASN1Type {
    private static final ASN1Any ASN1 = new ASN1Any();

    public ASN1Any() {
        super(0);
    }

    public static ASN1Any getInstance() {
        return ASN1;
    }

    public final boolean checkTag(int identifier) {
        return true;
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readContent();
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        byte[] bytesEncoded = new byte[(in.offset - in.tagOffset)];
        System.arraycopy(in.buffer, in.tagOffset, bytesEncoded, 0, bytesEncoded.length);
        return bytesEncoded;
    }

    public void encodeASN(BerOutputStream out) {
        out.encodeANY();
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeANY();
    }

    public void setEncodingContent(BerOutputStream out) {
        out.length = ((byte[]) out.content).length;
    }

    public int getEncodedLength(BerOutputStream out) {
        return out.length;
    }
}
