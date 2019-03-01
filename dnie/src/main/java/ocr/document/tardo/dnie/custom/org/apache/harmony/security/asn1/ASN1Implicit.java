package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;

public class ASN1Implicit extends ASN1Type {
    private static final int TAGGING_CONSTRUCTED = 1;
    private static final int TAGGING_PRIMITIVE = 0;
    private static final int TAGGING_STRING = 2;
    private final int taggingType;
    private final ASN1Type type;

    public ASN1Implicit(int tagNumber, ASN1Type type) {
        this(128, tagNumber, type);
    }

    public ASN1Implicit(int tagClass, int tagNumber, ASN1Type type) {
        super(tagClass, tagNumber);
        if ((type instanceof ASN1Choice) || (type instanceof ASN1Any)) {
            throw new IllegalArgumentException(Messages.getString("security.9F"));
        }
        this.type = type;
        if (!type.checkTag(type.id)) {
            this.taggingType = 1;
        } else if (type.checkTag(type.constrId)) {
            this.taggingType = 2;
        } else {
            this.taggingType = 0;
        }
    }

    public final boolean checkTag(int identifier) {
        boolean z = false;
        switch (this.taggingType) {
            case 0:
                if (this.id != identifier) {
                    return false;
                }
                return true;
            case 1:
                if (this.constrId != identifier) {
                    return false;
                }
                return true;
            default:
                if (this.id == identifier || this.constrId == identifier) {
                    z = true;
                }
                return z;
        }
    }

    public Object decode(BerInputStream in) throws IOException {
        if (checkTag(in.tag)) {
            if (this.id == in.tag) {
                in.tag = this.type.id;
            } else {
                in.tag = this.type.constrId;
            }
            in.content = this.type.decode(in);
            if (in.isVerify) {
                return null;
            }
            return getDecodedObject(in);
        }
        throw new ASN1Exception(Messages.getString("security.100", new Object[]{Integer.valueOf(in.tagOffset), Integer.toHexString(this.id), Integer.toHexString(in.tag)}));
    }

    public void encodeASN(BerOutputStream out) {
        if (this.taggingType == 1) {
            out.encodeTag(this.constrId);
        } else {
            out.encodeTag(this.id);
        }
        encodeContent(out);
    }

    public void encodeContent(BerOutputStream out) {
        this.type.encodeContent(out);
    }

    public void setEncodingContent(BerOutputStream out) {
        this.type.setEncodingContent(out);
    }
}
