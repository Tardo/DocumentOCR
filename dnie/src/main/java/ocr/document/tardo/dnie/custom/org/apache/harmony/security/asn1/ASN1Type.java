package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.eac.CertificateBody;

public abstract class ASN1Type implements ASN1Constants {
    public final int constrId;
    public final int id;

    public abstract boolean checkTag(int i);

    public abstract Object decode(BerInputStream berInputStream) throws IOException;

    public abstract void encodeASN(BerOutputStream berOutputStream);

    public abstract void encodeContent(BerOutputStream berOutputStream);

    public abstract void setEncodingContent(BerOutputStream berOutputStream);

    public ASN1Type(int tagNumber) {
        this(0, tagNumber);
    }

    public ASN1Type(int tagClass, int tagNumber) {
        if (tagNumber < 0) {
            throw new IllegalArgumentException(Messages.getString("security.102"));
        } else if (tagClass != 0 && tagClass != 64 && tagClass != 128 && tagClass != 192) {
            throw new IllegalArgumentException(Messages.getString("security.103"));
        } else if (tagNumber < 31) {
            this.id = tagClass + tagNumber;
            this.constrId = this.id + 32;
        } else {
            throw new IllegalArgumentException(Messages.getString("security.104"));
        }
    }

    public final Object decode(byte[] encoded) throws IOException {
        return decode(new DerInputStream(encoded));
    }

    public final Object decode(byte[] encoded, int offset, int encodingLen) throws IOException {
        return decode(new DerInputStream(encoded, offset, encodingLen));
    }

    public final Object decode(InputStream in) throws IOException {
        return decode(new DerInputStream(in));
    }

    public final void verify(byte[] encoded) throws IOException {
        BerInputStream decoder = new DerInputStream(encoded);
        decoder.setVerify();
        decode(decoder);
    }

    public final void verify(InputStream in) throws IOException {
        BerInputStream decoder = new DerInputStream(in);
        decoder.setVerify();
        decode(decoder);
    }

    public final byte[] encode(Object object) {
        return new DerOutputStream(this, object).encoded;
    }

    protected Object getDecodedObject(BerInputStream in) throws IOException {
        return in.content;
    }

    public int getEncodedLength(BerOutputStream out) {
        int len = 1 + 1;
        if (out.length > CertificateBody.profileType) {
            len++;
            int cur = out.length >> 8;
            while (cur > 0) {
                cur >>= 8;
                len++;
            }
        }
        return len + out.length;
    }

    public String toString() {
        return getClass().getName() + "(tag: 0x" + Integer.toHexString(this.id & 255) + ")";
    }
}
