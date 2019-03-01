package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.net.ssl.SSLHandshakeException;

public class HandshakeIODataStream extends SSLInputStream implements Appendable, DataStream {
    private static final MessageDigest md5;
    private static final MessageDigest sha;
    private int buff_size = 1024;
    private byte[] buffer = new byte[this.buff_size];
    private int inc_buff_size = 1024;
    private int marked_pos;
    private int read_pos;
    private int read_pos_end;
    private int write_pos;
    private int write_pos_beg;

    static {
        try {
            md5 = MessageDigest.getInstance("MD5");
            sha = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Could not initialize the Digest Algorithms.");
        }
    }

    public int available() {
        return this.read_pos_end - this.read_pos;
    }

    public boolean markSupported() {
        return true;
    }

    public void mark(int limit) {
        this.marked_pos = this.read_pos;
    }

    public void mark() {
        this.marked_pos = this.read_pos;
    }

    public void reset() {
        this.read_pos = this.marked_pos;
    }

    protected void removeFromMarkedPosition() {
        System.arraycopy(this.buffer, this.read_pos, this.buffer, this.marked_pos, this.read_pos_end - this.read_pos);
        this.read_pos_end -= this.read_pos - this.marked_pos;
        this.read_pos = this.marked_pos;
    }

    public int read() throws IOException {
        if (this.read_pos == this.read_pos_end) {
            throw new EndOfBufferException();
        }
        byte[] bArr = this.buffer;
        int i = this.read_pos;
        this.read_pos = i + 1;
        return bArr[i] & 255;
    }

    public byte[] read(int length) throws IOException {
        if (length > available()) {
            throw new EndOfBufferException();
        }
        byte[] res = new byte[length];
        System.arraycopy(this.buffer, this.read_pos, res, 0, length);
        this.read_pos += length;
        return res;
    }

    public int read(byte[] dest, int offset, int length) throws IOException {
        if (length > available()) {
            throw new EndOfBufferException();
        }
        System.arraycopy(this.buffer, this.read_pos, dest, offset, length);
        this.read_pos += length;
        return length;
    }

    public void append(byte[] src) {
        append(src, 0, src.length);
    }

    private void append(byte[] src, int from, int length) {
        if (this.read_pos == this.read_pos_end) {
            if (this.write_pos_beg != this.write_pos) {
                throw new AlertException((byte) 10, new SSLHandshakeException("Handshake message has been received before the last oubound message had been sent."));
            } else if (this.read_pos < this.write_pos) {
                this.read_pos = this.write_pos;
                this.read_pos_end = this.read_pos;
            }
        }
        if (this.read_pos_end + length > this.buff_size) {
            enlargeBuffer((this.read_pos_end + length) - this.buff_size);
        }
        System.arraycopy(src, from, this.buffer, this.read_pos_end, length);
        this.read_pos_end += length;
    }

    private void enlargeBuffer(int size) {
        this.buff_size = size < this.inc_buff_size ? this.buff_size + this.inc_buff_size : this.buff_size + size;
        byte[] new_buff = new byte[this.buff_size];
        System.arraycopy(this.buffer, 0, new_buff, 0, this.buffer.length);
        this.buffer = new_buff;
    }

    protected void clearBuffer() {
        this.read_pos = 0;
        this.marked_pos = 0;
        this.read_pos_end = 0;
        this.write_pos = 0;
        this.write_pos_beg = 0;
        Arrays.fill(this.buffer, (byte) 0);
    }

    private void check(int length) {
        if (this.write_pos == this.write_pos_beg) {
            if (this.read_pos != this.read_pos_end) {
                throw new AlertException((byte) 80, new SSLHandshakeException("Data was not fully read: " + this.read_pos + " " + this.read_pos_end));
            } else if (this.write_pos_beg < this.read_pos_end) {
                this.write_pos_beg = this.read_pos_end;
                this.write_pos = this.write_pos_beg;
            }
        }
        if (this.write_pos + length >= this.buff_size) {
            enlargeBuffer(length);
        }
    }

    public void write(byte b) {
        check(1);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = b;
    }

    public void writeUint8(long n) {
        check(1);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) (255 & n));
    }

    public void writeUint16(long n) {
        check(2);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((65280 & n) >> 8));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) (255 & n));
    }

    public void writeUint24(long n) {
        check(3);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((16711680 & n) >> 16));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((65280 & n) >> 8));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) (255 & n));
    }

    public void writeUint32(long n) {
        check(4);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((-16777216 & n) >> 24));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((16711680 & n) >> 16));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((65280 & n) >> 8));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) (255 & n));
    }

    public void writeUint64(long n) {
        check(8);
        byte[] bArr = this.buffer;
        int i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((-72057594037927936L & n) >> 56));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((71776119061217280L & n) >> 48));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((280375465082880L & n) >> 40));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((1095216660480L & n) >> 32));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((-16777216 & n) >> 24));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((16711680 & n) >> 16));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) ((65280 & n) >> 8));
        bArr = this.buffer;
        i = this.write_pos;
        this.write_pos = i + 1;
        bArr[i] = (byte) ((int) (255 & n));
    }

    public void write(byte[] vector) {
        check(vector.length);
        System.arraycopy(vector, 0, this.buffer, this.write_pos, vector.length);
        this.write_pos += vector.length;
    }

    public boolean hasData() {
        return this.write_pos > this.write_pos_beg;
    }

    public byte[] getData(int length) {
        if (this.write_pos - this.write_pos_beg < length) {
            byte[] res = new byte[(this.write_pos - this.write_pos_beg)];
            System.arraycopy(this.buffer, this.write_pos_beg, res, 0, this.write_pos - this.write_pos_beg);
            this.write_pos_beg = this.write_pos;
            return res;
        }
        res = new byte[length];
        System.arraycopy(this.buffer, this.write_pos_beg, res, 0, length);
        this.write_pos_beg += length;
        return res;
    }

    protected void printContent(PrintStream outstream) {
        String prefix = " ";
        String delimiter = "";
        for (int i = this.write_pos_beg; i < this.write_pos; i++) {
            String tail = Integer.toHexString(this.buffer[i] & 255).toUpperCase();
            if (tail.length() == 1) {
                tail = "0" + tail;
            }
            outstream.print(prefix + tail + delimiter);
            if (((i - this.write_pos_beg) + 1) % 10 == 0) {
                outstream.print(" ");
            }
            if (((i - this.write_pos_beg) + 1) % 20 == 0) {
                outstream.println();
            }
        }
        outstream.println();
    }

    protected byte[] getDigestMD5() {
        byte[] digest;
        synchronized (md5) {
            md5.update(this.buffer, 0, this.read_pos_end > this.write_pos ? this.read_pos_end : this.write_pos);
            digest = md5.digest();
        }
        return digest;
    }

    protected byte[] getDigestSHA() {
        byte[] digest;
        synchronized (sha) {
            sha.update(this.buffer, 0, this.read_pos_end > this.write_pos ? this.read_pos_end : this.write_pos);
            digest = sha.digest();
        }
        return digest;
    }

    protected byte[] getDigestMD5withoutLast() {
        byte[] digest;
        synchronized (md5) {
            md5.update(this.buffer, 0, this.marked_pos);
            digest = md5.digest();
        }
        return digest;
    }

    protected byte[] getDigestSHAwithoutLast() {
        byte[] digest;
        synchronized (sha) {
            sha.update(this.buffer, 0, this.marked_pos);
            digest = sha.digest();
        }
        return digest;
    }

    protected byte[] getMessages() {
        int len = this.read_pos_end > this.write_pos ? this.read_pos_end : this.write_pos;
        byte[] res = new byte[len];
        System.arraycopy(this.buffer, 0, res, 0, len);
        return res;
    }
}
