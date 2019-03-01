package jj2000.j2k.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import jj2000.j2k.io.RandomAccessIO;

public class ISRandomAccessIO implements RandomAccessIO {
    private byte[] buf;
    private boolean complete;
    private int inc;
    private InputStream is;
    private int len;
    private int maxsize;
    private int pos;

    public ISRandomAccessIO(InputStream is, int size, int inc, int maxsize) {
        if (size < 0 || inc <= 0 || maxsize <= 0 || is == null) {
            throw new IllegalArgumentException();
        }
        this.is = is;
        if (size < Integer.MAX_VALUE) {
            size++;
        }
        this.buf = new byte[size];
        this.inc = inc;
        if (maxsize < Integer.MAX_VALUE) {
            maxsize++;
        }
        this.maxsize = maxsize;
        this.pos = 0;
        this.len = 0;
        this.complete = false;
    }

    public ISRandomAccessIO(InputStream is) {
        this(is, 262144, 262144, Integer.MAX_VALUE);
    }

    private void growBuffer() throws IOException {
        int effinc = this.inc;
        if (this.buf.length + effinc > this.maxsize) {
            effinc = this.maxsize - this.buf.length;
        }
        if (effinc <= 0) {
            throw new IOException("Reached maximum cache size (" + this.maxsize + ")");
        }
        try {
            byte[] newbuf = new byte[(this.buf.length + this.inc)];
            System.arraycopy(this.buf, 0, newbuf, 0, this.len);
            this.buf = newbuf;
        } catch (OutOfMemoryError e) {
            throw new IOException("Out of memory to cache input data");
        }
    }

    private void readInput() throws IOException {
        if (this.complete) {
            throw new IllegalArgumentException("Already reached EOF");
        }
        int n = this.is.available();
        if (n == 0) {
            n = 1;
        }
        while (this.len + n > this.buf.length) {
            growBuffer();
        }
        int k;
        do {
            k = this.is.read(this.buf, this.len, n);
            if (k > 0) {
                this.len += k;
                n -= k;
            }
            if (n <= 0) {
                break;
            }
        } while (k > 0);
        if (k <= 0) {
            this.complete = true;
            this.is.close();
            this.is = null;
        }
    }

    public void close() throws IOException {
        this.buf = null;
        if (!this.complete) {
            this.is.close();
            this.is = null;
        }
    }

    public int getPos() throws IOException {
        return this.pos;
    }

    public void seek(int off) throws IOException {
        if (!this.complete || off <= this.len) {
            this.pos = off;
            return;
        }
        throw new EOFException();
    }

    public int length() throws IOException {
        while (!this.complete) {
            readInput();
        }
        return this.len;
    }

    public int read() throws IOException {
        if (this.pos < this.len) {
            byte[] bArr = this.buf;
            int i = this.pos;
            this.pos = i + 1;
            return bArr[i] & 255;
        }
        while (!this.complete && this.pos >= this.len) {
            readInput();
        }
        if (this.pos == this.len) {
            throw new EOFException();
        } else if (this.pos > this.len) {
            throw new IOException("Position beyond EOF");
        } else {
            bArr = this.buf;
            i = this.pos;
            this.pos = i + 1;
            return bArr[i] & 255;
        }
    }

    public void readFully(byte[] b, int off, int n) throws IOException {
        if (this.pos + n <= this.len) {
            System.arraycopy(this.buf, this.pos, b, off, n);
            this.pos += n;
            return;
        }
        while (!this.complete && this.pos + n > this.len) {
            readInput();
        }
        if (this.pos + n > this.len) {
            throw new EOFException();
        }
        System.arraycopy(this.buf, this.pos, b, off, n);
        this.pos += n;
    }

    public int getByteOrdering() {
        return 0;
    }

    public byte readByte() throws IOException {
        if (this.pos >= this.len) {
            return (byte) read();
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        return bArr[i];
    }

    public int readUnsignedByte() throws IOException {
        if (this.pos >= this.len) {
            return read();
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        return bArr[i] & 255;
    }

    public short readShort() throws IOException {
        if (this.pos + 1 >= this.len) {
            return (short) ((read() << 8) | read());
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = bArr[i] << 8;
        byte[] bArr2 = this.buf;
        int i3 = this.pos;
        this.pos = i3 + 1;
        return (short) (i2 | (bArr2[i3] & 255));
    }

    public int readUnsignedShort() throws IOException {
        if (this.pos + 1 >= this.len) {
            return (read() << 8) | read();
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = (bArr[i] & 255) << 8;
        byte[] bArr2 = this.buf;
        int i3 = this.pos;
        this.pos = i3 + 1;
        return i2 | (bArr2[i3] & 255);
    }

    public int readInt() throws IOException {
        if (this.pos + 3 >= this.len) {
            return (((read() << 24) | (read() << 16)) | (read() << 8)) | read();
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = bArr[i] << 24;
        byte[] bArr2 = this.buf;
        int i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 16;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 8;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        return i2 | (bArr2[i3] & 255);
    }

    public long readUnsignedInt() throws IOException {
        if (this.pos + 3 >= this.len) {
            return ((long) ((((read() << 24) | (read() << 16)) | (read() << 8)) | read())) & 4294967295L;
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = bArr[i] << 24;
        byte[] bArr2 = this.buf;
        int i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 16;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 8;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        return ((long) (i2 | (bArr2[i3] & 255))) & 4294967295L;
    }

    public long readLong() throws IOException {
        if (this.pos + 7 >= this.len) {
            return (((((((((long) read()) << 56) | (((long) read()) << 48)) | (((long) read()) << 40)) | (((long) read()) << 32)) | (((long) read()) << 24)) | (((long) read()) << 16)) | (((long) read()) << 8)) | ((long) read());
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        long j = ((long) bArr[i]) << 56;
        byte[] bArr2 = this.buf;
        int i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 48;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 40;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 32;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 24;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 16;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 8;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        return j | ((long) (bArr2[i2] & 255));
    }

    public float readFloat() throws IOException {
        if (this.pos + 3 >= this.len) {
            return Float.intBitsToFloat((((read() << 24) | (read() << 16)) | (read() << 8)) | read());
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = bArr[i] << 24;
        byte[] bArr2 = this.buf;
        int i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 16;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        i2 |= (bArr2[i3] & 255) << 8;
        bArr2 = this.buf;
        i3 = this.pos;
        this.pos = i3 + 1;
        return Float.intBitsToFloat(i2 | (bArr2[i3] & 255));
    }

    public double readDouble() throws IOException {
        if (this.pos + 7 >= this.len) {
            return Double.longBitsToDouble((((((((((long) read()) << 56) | (((long) read()) << 48)) | (((long) read()) << 40)) | (((long) read()) << 32)) | (((long) read()) << 24)) | (((long) read()) << 16)) | (((long) read()) << 8)) | ((long) read()));
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        long j = ((long) bArr[i]) << 56;
        byte[] bArr2 = this.buf;
        int i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 48;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 40;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 32;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 24;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 16;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        j |= ((long) (bArr2[i2] & 255)) << 8;
        bArr2 = this.buf;
        i2 = this.pos;
        this.pos = i2 + 1;
        return Double.longBitsToDouble(j | ((long) (bArr2[i2] & 255)));
    }

    public int skipBytes(int n) throws IOException {
        if (!this.complete || this.pos + n <= this.len) {
            this.pos += n;
            return n;
        }
        throw new EOFException();
    }

    public void flush() {
    }

    public void write(int b) throws IOException {
        throw new IOException("read-only");
    }

    public void writeByte(int v) throws IOException {
        throw new IOException("read-only");
    }

    public void writeShort(int v) throws IOException {
        throw new IOException("read-only");
    }

    public void writeInt(int v) throws IOException {
        throw new IOException("read-only");
    }

    public void writeLong(long v) throws IOException {
        throw new IOException("read-only");
    }

    public void writeFloat(float v) throws IOException {
        throw new IOException("read-only");
    }

    public void writeDouble(double v) throws IOException {
        throw new IOException("read-only");
    }
}
