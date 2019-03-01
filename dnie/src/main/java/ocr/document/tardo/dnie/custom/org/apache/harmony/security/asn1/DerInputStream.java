package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import java.io.IOException;
import java.io.InputStream;

public final class DerInputStream extends BerInputStream {
    private static final byte[] UNUSED_BITS_MASK = new byte[]{(byte) 1, (byte) 3, (byte) 7, Handshake.CERTIFICATE_VERIFY, (byte) 31, (byte) 63, Byte.MAX_VALUE};

    public DerInputStream(byte[] encoded) throws IOException {
        super(encoded, 0, encoded.length);
    }

    public DerInputStream(byte[] encoded, int offset, int encodingLen) throws IOException {
        super(encoded, offset, encodingLen);
    }

    public DerInputStream(InputStream in) throws IOException {
        super(in);
    }

    public final int next() throws IOException {
        int tag = super.next();
        if (this.length != -1) {
            return tag;
        }
        throw new ASN1Exception(Messages.getString("security.105"));
    }

    public void readBitString() throws IOException {
        if (this.tag == 35) {
            throw new ASN1Exception(Messages.getString("security.106", this.tagOffset));
        }
        super.readBitString();
        if (this.length > 1 && this.buffer[this.contentOffset] != (byte) 0 && (this.buffer[this.offset - 1] & UNUSED_BITS_MASK[this.buffer[this.contentOffset] - 1]) != 0) {
            throw new ASN1Exception(Messages.getString("security.107", this.contentOffset));
        }
    }

    public void readBoolean() throws IOException {
        super.readBoolean();
        if (this.buffer[this.contentOffset] != (byte) 0 && this.buffer[this.contentOffset] != (byte) -1) {
            throw new ASN1Exception(Messages.getString("security.108", this.contentOffset));
        }
    }

    public void readOctetString() throws IOException {
        if (this.tag == 36) {
            throw new ASN1Exception(Messages.getString("security.109", this.tagOffset));
        }
        super.readOctetString();
    }

    public void readSequence(ASN1Sequence sequence) throws IOException {
        super.readSequence(sequence);
    }

    public void readSetOf(ASN1SetOf setOf) throws IOException {
        super.readSetOf(setOf);
    }

    public void readString(ASN1StringType type) throws IOException {
        if (this.tag == type.constrId) {
            throw new ASN1Exception(Messages.getString("security.10A", this.tagOffset));
        }
        super.readString(type);
    }

    public void readUTCTime() throws IOException {
        if (this.tag == 55) {
            throw new ASN1Exception(Messages.getString("security.10B", this.tagOffset));
        } else if (this.length != 13) {
            throw new ASN1Exception(Messages.getString("security.10C", this.tagOffset));
        } else {
            super.readUTCTime();
        }
    }

    public void readGeneralizedTime() throws IOException {
        if (this.tag == 56) {
            throw new ASN1Exception(Messages.getString("security.10D", this.tagOffset));
        }
        super.readGeneralizedTime();
    }
}
