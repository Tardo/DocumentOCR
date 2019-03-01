package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.util.ArrayList;
import org.bouncycastle.asn1.eac.CertificateBody;

public class BerInputStream {
    private static final int BUF_INCREASE_SIZE = 16384;
    protected static final int INDEFINIT_LENGTH = -1;
    protected byte[] buffer;
    public int choiceIndex;
    public Object content;
    protected int contentOffset;
    protected InputStream in;
    protected boolean isIndefinedLength;
    protected boolean isVerify;
    protected int length;
    protected int offset;
    public int oidElement;
    private Object[][] pool;
    public int tag;
    protected int tagOffset;
    public int[] times;

    public BerInputStream(byte[] encoded) throws IOException {
        this(encoded, 0, encoded.length);
    }

    public BerInputStream(byte[] encoded, int offset, int expectedLength) throws IOException {
        this.offset = 0;
        this.buffer = encoded;
        this.offset = offset;
        next();
        if (this.length != -1 && offset + expectedLength != this.offset + this.length) {
            throw new ASN1Exception(Messages.getString("security.111"));
        }
    }

    public BerInputStream(InputStream in) throws IOException {
        this(in, 16384);
    }

    public BerInputStream(InputStream in, int initialSize) throws IOException {
        this.offset = 0;
        this.in = in;
        this.buffer = new byte[initialSize];
        next();
        if (this.length == -1) {
            this.isIndefinedLength = true;
            throw new ASN1Exception(Messages.getString("security.112"));
        } else if (this.buffer.length < this.length + this.offset) {
            byte[] newBuffer = new byte[(this.length + this.offset)];
            System.arraycopy(this.buffer, 0, newBuffer, 0, this.offset);
            this.buffer = newBuffer;
        }
    }

    public final void reset(byte[] encoded) throws IOException {
        this.buffer = encoded;
        next();
    }

    public int next() throws IOException {
        this.tagOffset = this.offset;
        this.tag = read();
        this.length = read();
        if (this.length == 128) {
            this.length = -1;
        } else if ((this.length & 128) != 0) {
            int numOctets = this.length & CertificateBody.profileType;
            if (numOctets > 5) {
                throw new ASN1Exception(Messages.getString("security.113", this.tagOffset));
            }
            this.length = read();
            for (int i = 1; i < numOctets; i++) {
                this.length = (this.length << 8) + read();
            }
            if (this.length > 16777215) {
                throw new ASN1Exception(Messages.getString("security.113", this.tagOffset));
            }
        }
        this.contentOffset = this.offset;
        return this.tag;
    }

    public static int getLength(byte[] encoding) {
        int length = encoding[1] & 255;
        int numOctets = 0;
        if ((length & 128) != 0) {
            numOctets = length & CertificateBody.profileType;
            length = encoding[2] & 255;
            for (int i = 3; i < numOctets + 2; i++) {
                length = (length << 8) + (encoding[i] & 255);
            }
        }
        return (numOctets + 2) + length;
    }

    public void readBitString() throws IOException {
        if (this.tag == 3) {
            if (this.length == 0) {
                throw new ASN1Exception(Messages.getString("security.114", this.tagOffset));
            }
            readContent();
            if (this.buffer[this.contentOffset] > (byte) 7) {
                throw new ASN1Exception(Messages.getString("security.115", this.contentOffset));
            } else if (this.length == 1 && this.buffer[this.contentOffset] != (byte) 0) {
                throw new ASN1Exception(Messages.getString("security.116", this.contentOffset));
            }
        } else if (this.tag == 35) {
            throw new ASN1Exception(Messages.getString("security.117"));
        } else {
            throw new ASN1Exception(Messages.getString("security.118", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
    }

    public void readEnumerated() throws IOException {
        if (this.tag != 10) {
            throw new ASN1Exception(Messages.getString("security.119", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        } else if (this.length == 0) {
            throw new ASN1Exception(Messages.getString("security.11A", this.tagOffset));
        } else {
            readContent();
            if (this.length > 1) {
                int bits = this.buffer[this.contentOffset] & 255;
                if (this.buffer[this.contentOffset + 1] < (byte) 0) {
                    bits += 256;
                }
                if (bits == 0 || bits == 511) {
                    throw new ASN1Exception(Messages.getString("security.11B", this.contentOffset));
                }
            }
        }
    }

    public void readBoolean() throws IOException {
        if (this.tag != 1) {
            throw new ASN1Exception(Messages.getString("security.11C", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        } else if (this.length != 1) {
            throw new ASN1Exception(Messages.getString("security.11D", this.tagOffset));
        } else {
            readContent();
        }
    }

    public void readGeneralizedTime() throws IOException {
        if (this.tag == 24) {
            readContent();
            if (this.buffer[this.offset - 1] != (byte) 90) {
                throw new ASN1Exception(Messages.getString("security.11E"));
            } else if (this.length == 15 || (this.length >= 17 && this.length <= 19)) {
                if (this.length > 16) {
                    byte char14 = this.buffer[this.contentOffset + 14];
                    if (!(char14 == (byte) 46 || char14 == (byte) 44)) {
                        throw new ASN1Exception(Messages.getString("security.11F", this.contentOffset));
                    }
                }
                if (this.times == null) {
                    this.times = new int[7];
                }
                this.times[0] = strToInt(this.contentOffset, 4);
                this.times[1] = strToInt(this.contentOffset + 4, 2);
                this.times[2] = strToInt(this.contentOffset + 6, 2);
                this.times[3] = strToInt(this.contentOffset + 8, 2);
                this.times[4] = strToInt(this.contentOffset + 10, 2);
                this.times[5] = strToInt(this.contentOffset + 12, 2);
                if (this.length > 16) {
                    this.times[6] = strToInt(this.contentOffset + 15, this.length - 16);
                    if (this.length == 17) {
                        this.times[6] = this.times[6] * 100;
                    } else if (this.length == 18) {
                        this.times[6] = this.times[6] * 10;
                    }
                }
            } else {
                throw new ASN1Exception(Messages.getString("security.11F", this.contentOffset));
            }
        } else if (this.tag == 56) {
            throw new ASN1Exception(Messages.getString("security.120"));
        } else {
            throw new ASN1Exception(Messages.getString("security.121", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
    }

    public void readUTCTime() throws IOException {
        if (this.tag == 23) {
            switch (this.length) {
                case 11:
                case 13:
                    readContent();
                    if (this.buffer[this.offset - 1] != (byte) 90) {
                        throw new ASN1Exception("ASN.1 UTCTime wrongly encoded at [" + this.contentOffset + ']');
                    }
                    if (this.times == null) {
                        this.times = new int[7];
                    }
                    this.times[0] = strToInt(this.contentOffset, 2);
                    int[] iArr;
                    if (this.times[0] > 49) {
                        iArr = this.times;
                        iArr[0] = iArr[0] + 1900;
                    } else {
                        iArr = this.times;
                        iArr[0] = iArr[0] + 2000;
                    }
                    this.times[1] = strToInt(this.contentOffset + 2, 2);
                    this.times[2] = strToInt(this.contentOffset + 4, 2);
                    this.times[3] = strToInt(this.contentOffset + 6, 2);
                    this.times[4] = strToInt(this.contentOffset + 8, 2);
                    if (this.length == 13) {
                        this.times[5] = strToInt(this.contentOffset + 10, 2);
                        return;
                    }
                    return;
                case 15:
                case 17:
                    throw new ASN1Exception(Messages.getString("security.122"));
                default:
                    throw new ASN1Exception(Messages.getString("security.123", this.tagOffset));
            }
        } else if (this.tag == 55) {
            throw new ASN1Exception(Messages.getString("security.124"));
        } else {
            throw new ASN1Exception(Messages.getString("security.125", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
    }

    private int strToInt(int off, int count) throws ASN1Exception {
        int result = 0;
        int end = off + count;
        for (int i = off; i < end; i++) {
            int c = this.buffer[i] - 48;
            if (c < 0 || c > 9) {
                throw new ASN1Exception(Messages.getString("security.126"));
            }
            result = (result * 10) + c;
        }
        return result;
    }

    public void readInteger() throws IOException {
        if (this.tag != 2) {
            throw new ASN1Exception(Messages.getString("security.127", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        } else if (this.length < 1) {
            throw new ASN1Exception(Messages.getString("security.128", this.tagOffset));
        } else {
            readContent();
            if (this.length > 1) {
                byte firstByte = this.buffer[this.offset - this.length];
                byte secondByte = (byte) (this.buffer[(this.offset - this.length) + 1] & 128);
                if ((firstByte == (byte) 0 && secondByte == (byte) 0) || (firstByte == (byte) -1 && secondByte == Byte.MIN_VALUE)) {
                    throw new ASN1Exception(Messages.getString("security.129", this.offset - this.length));
                }
            }
        }
    }

    public void readOctetString() throws IOException {
        if (this.tag == 4) {
            readContent();
        } else if (this.tag == 36) {
            throw new ASN1Exception(Messages.getString("security.12A"));
        } else {
            throw new ASN1Exception(Messages.getString("security.12B", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
    }

    public void readOID() throws IOException {
        if (this.tag != 6) {
            throw new ASN1Exception(Messages.getString("security.12C", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        } else if (this.length < 1) {
            throw new ASN1Exception(Messages.getString("security.12D", this.tagOffset));
        } else {
            readContent();
            if ((this.buffer[this.offset - 1] & 128) != 0) {
                throw new ASN1Exception(Messages.getString("security.12E", this.offset - 1));
            }
            this.oidElement = 1;
            int i = 0;
            while (i < this.length) {
                while ((this.buffer[this.contentOffset + i] & 128) == 128) {
                    i++;
                }
                i++;
                this.oidElement++;
            }
        }
    }

    public void readSequence(ASN1Sequence sequence) throws IOException {
        if (this.tag != 48) {
            throw new ASN1Exception(Messages.getString("security.12F", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
        int begOffset = this.offset;
        int endOffset = begOffset + this.length;
        ASN1Type[] type = sequence.type;
        int i = 0;
        if (this.isVerify) {
            while (this.offset < endOffset && i < type.length) {
                next();
                while (!type[i].checkTag(this.tag)) {
                    if (!sequence.OPTIONAL[i] || i == type.length - 1) {
                        throw new ASN1Exception(Messages.getString("security.130", this.tagOffset));
                    }
                    i++;
                }
                type[i].decode(this);
                i++;
            }
            while (i < type.length) {
                if (sequence.OPTIONAL[i]) {
                    i++;
                } else {
                    throw new ASN1Exception(Messages.getString("security.131", this.tagOffset));
                }
            }
        }
        int seqTagOffset = this.tagOffset;
        Object[] values = new Object[type.length];
        while (this.offset < endOffset && i < type.length) {
            next();
            while (!type[i].checkTag(this.tag)) {
                if (!sequence.OPTIONAL[i] || i == type.length - 1) {
                    throw new ASN1Exception(Messages.getString("security.132", this.tagOffset));
                }
                if (sequence.DEFAULT[i] != null) {
                    values[i] = sequence.DEFAULT[i];
                }
                i++;
            }
            values[i] = type[i].decode(this);
            i++;
        }
        while (i < type.length) {
            if (sequence.OPTIONAL[i]) {
                if (sequence.DEFAULT[i] != null) {
                    values[i] = sequence.DEFAULT[i];
                }
                i++;
            } else {
                throw new ASN1Exception(Messages.getString("security.133", this.tagOffset));
            }
        }
        this.content = values;
        this.tagOffset = seqTagOffset;
        if (this.offset != endOffset) {
            throw new ASN1Exception(Messages.getString("security.134", begOffset));
        }
    }

    public void readSequenceOf(ASN1SequenceOf sequenceOf) throws IOException {
        if (this.tag != 48) {
            throw new ASN1Exception(Messages.getString("security.135", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
        decodeValueCollection(sequenceOf);
    }

    public void readSet(ASN1Set set) throws IOException {
        if (this.tag != 49) {
            throw new ASN1Exception(Messages.getString("security.136", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
        throw new ASN1Exception(Messages.getString("security.137"));
    }

    public void readSetOf(ASN1SetOf setOf) throws IOException {
        if (this.tag != 49) {
            throw new ASN1Exception(Messages.getString("security.138", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
        decodeValueCollection(setOf);
    }

    private final void decodeValueCollection(ASN1ValueCollection collection) throws IOException {
        int begOffset = this.offset;
        int endOffset = begOffset + this.length;
        ASN1Type type = collection.type;
        if (this.isVerify) {
            while (endOffset > this.offset) {
                next();
                type.decode(this);
            }
        } else {
            int seqTagOffset = this.tagOffset;
            ArrayList values = new ArrayList();
            while (endOffset > this.offset) {
                next();
                values.add(type.decode(this));
            }
            this.content = values;
            this.tagOffset = seqTagOffset;
        }
        if (this.offset != endOffset) {
            throw new ASN1Exception(Messages.getString("security.134", begOffset));
        }
    }

    public void readString(ASN1StringType type) throws IOException {
        if (this.tag == type.id) {
            readContent();
        } else if (this.tag == type.constrId) {
            throw new ASN1Exception(Messages.getString("security.139"));
        } else {
            throw new ASN1Exception(Messages.getString("security.13A", Integer.valueOf(this.tagOffset), Integer.toHexString(this.tag)));
        }
    }

    public byte[] getEncoded() {
        byte[] encoded = new byte[(this.offset - this.tagOffset)];
        System.arraycopy(this.buffer, this.tagOffset, encoded, 0, encoded.length);
        return encoded;
    }

    public final byte[] getBuffer() {
        return this.buffer;
    }

    public final int getLength() {
        return this.length;
    }

    public final int getOffset() {
        return this.offset;
    }

    public final int getEndOffset() {
        return this.offset + this.length;
    }

    public final int getTagOffset() {
        return this.tagOffset;
    }

    public final int getContentOffset() {
        return this.contentOffset;
    }

    public final void setVerify() {
        this.isVerify = true;
    }

    protected int read() throws IOException {
        if (this.offset == this.buffer.length) {
            throw new ASN1Exception(Messages.getString("security.13B"));
        } else if (this.in == null) {
            r1 = this.buffer;
            r2 = this.offset;
            this.offset = r2 + 1;
            return r1[r2] & 255;
        } else {
            int octet = this.in.read();
            if (octet == -1) {
                throw new ASN1Exception(Messages.getString("security.13B"));
            }
            r1 = this.buffer;
            r2 = this.offset;
            this.offset = r2 + 1;
            r1[r2] = (byte) octet;
            return octet;
        }
    }

    public void readContent() throws IOException {
        if (this.offset + this.length > this.buffer.length) {
            throw new ASN1Exception(Messages.getString("security.13B"));
        } else if (this.in == null) {
            this.offset += this.length;
        } else {
            int bytesRead = this.in.read(this.buffer, this.offset, this.length);
            if (bytesRead != this.length) {
                int c = bytesRead;
                while (c >= 1 && bytesRead <= this.length) {
                    c = this.in.read(this.buffer, this.offset + bytesRead, this.length - bytesRead);
                    bytesRead += c;
                    if (bytesRead == this.length) {
                    }
                }
                throw new ASN1Exception(Messages.getString("security.13C"));
            }
            this.offset += this.length;
        }
    }

    public void compactBuffer() {
        if (this.offset != this.buffer.length) {
            byte[] newBuffer = new byte[this.offset];
            System.arraycopy(this.buffer, 0, newBuffer, 0, this.offset);
            this.buffer = newBuffer;
        }
    }

    public void put(Object key, Object entry) {
        if (this.pool == null) {
            this.pool = (Object[][]) Array.newInstance(Object.class, new int[]{2, 10});
        }
        int i = 0;
        while (i < this.pool[0].length && this.pool[0][i] != null) {
            if (this.pool[0][i] == key) {
                this.pool[1][i] = entry;
                return;
            }
            i++;
        }
        if (i == this.pool[0].length) {
            Object[][] newPool = (Object[][]) Array.newInstance(Object.class, new int[]{this.pool[0].length * 2, 2});
            System.arraycopy(this.pool[0], 0, newPool[0], 0, this.pool[0].length);
            System.arraycopy(this.pool[1], 0, newPool[1], 0, this.pool[0].length);
            this.pool = newPool;
            return;
        }
        this.pool[0][i] = key;
        this.pool[1][i] = entry;
    }

    public Object get(Object key) {
        if (this.pool == null) {
            return null;
        }
        for (int i = 0; i < this.pool[0].length; i++) {
            if (this.pool[0][i] == key) {
                return this.pool[1][i];
            }
        }
        return null;
    }
}
