package custom.org.apache.harmony.security.pkcs7;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;
import java.util.Arrays;

public class ContentInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), new ASN1Explicit(0, ASN1Any.getInstance())}) {
        protected void getValues(Object object, Object[] values) {
            ContentInfo ci = (ContentInfo) object;
            values[0] = ci.oid;
            if (ci.content == null) {
                return;
            }
            if (Arrays.equals(ci.oid, ContentInfo.DATA)) {
                if (ci.content != null) {
                    values[1] = ASN1OctetString.getInstance().encode(ci.content);
                }
            } else if (ci.content instanceof SignedData) {
                values[1] = SignedData.ASN1.encode(ci.content);
            } else {
                values[1] = ci.content;
            }
        }

        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            int[] oid = (int[]) values[0];
            if (Arrays.equals(oid, ContentInfo.DATA)) {
                if (values[1] != null) {
                    return new ContentInfo(oid, ASN1OctetString.getInstance().decode((byte[]) values[1]), in.getEncoded());
                }
                return new ContentInfo((int[]) values[0], null, in.getEncoded());
            } else if (Arrays.equals(oid, ContentInfo.SIGNED_DATA)) {
                return new ContentInfo((int[]) values[0], SignedData.ASN1.decode((byte[]) values[1]), in.getEncoded());
            } else {
                return new ContentInfo((int[]) values[0], (byte[]) values[1], in.getEncoded());
            }
        }
    };
    public static final int[] DATA = new int[]{1, 2, 840, 113549, 1, 7, 1};
    public static final int[] DIGESTED_DATA = new int[]{1, 2, 840, 113549, 1, 7, 5};
    public static final int[] ENCRYPTED_DATA = new int[]{1, 2, 840, 113549, 1, 7, 6};
    public static final int[] ENVELOPED_DATA = new int[]{1, 2, 840, 113549, 1, 7, 3};
    public static final int[] SIGNED_AND_ENVELOPED_DATA = new int[]{1, 2, 840, 113549, 1, 7, 4};
    public static final int[] SIGNED_DATA = new int[]{1, 2, 840, 113549, 1, 7, 2};
    private Object content;
    private byte[] encoding;
    private int[] oid;

    public ContentInfo(int[] oid, Object content) {
        this.oid = oid;
        this.content = content;
    }

    private ContentInfo(int[] oid, Object content, byte[] encoding) {
        this.oid = oid;
        this.content = content;
        this.encoding = encoding;
    }

    public SignedData getSignedData() {
        if (Arrays.equals(this.oid, SIGNED_DATA)) {
            return (SignedData) this.content;
        }
        return null;
    }

    public Object getContent() {
        return this.content;
    }

    public int[] getContentType() {
        return this.oid;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("==== ContentInfo:");
        res.append("\n== ContentType (OID): ");
        for (int append : this.oid) {
            res.append(append);
            res.append(' ');
        }
        res.append("\n== Content: ");
        if (this.content != null) {
            res.append("\n");
            res.append(this.content.toString());
        }
        res.append("\n== Content End");
        res.append("\n==== ContentInfo End\n");
        return res.toString();
    }
}
