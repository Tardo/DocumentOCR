package jj2000.j2k.entropy.decoder;

import java.io.EOFException;
import java.io.IOException;

public class ByteInputBuffer {
    private byte[] buf;
    private int count;
    private int pos;

    public ByteInputBuffer(byte[] buf) {
        this.buf = buf;
        this.count = buf.length;
    }

    public ByteInputBuffer(byte[] buf, int offset, int length) {
        this.buf = buf;
        this.pos = offset;
        this.count = offset + length;
    }

    public void setByteArray(byte[] buf, int offset, int length) {
        if (buf == null) {
            if (length < 0 || this.count + length > this.buf.length) {
                throw new IllegalArgumentException();
            } else if (offset < 0) {
                this.pos = this.count;
                this.count += length;
            } else {
                this.count = offset + length;
                this.pos = offset;
            }
        } else if (offset < 0 || length < 0 || offset + length > buf.length) {
            throw new IllegalArgumentException();
        } else {
            this.buf = buf;
            this.count = offset + length;
            this.pos = offset;
        }
    }

    public synchronized void addByteArray(byte[] data, int off, int len) {
        if (len >= 0 && off >= 0) {
            if (len + off <= this.buf.length) {
                if (this.count + len <= this.buf.length) {
                    System.arraycopy(data, off, this.buf, this.count, len);
                    this.count += len;
                } else {
                    if ((this.count - this.pos) + len <= this.buf.length) {
                        System.arraycopy(this.buf, this.pos, this.buf, 0, this.count - this.pos);
                    } else {
                        byte[] oldbuf = this.buf;
                        this.buf = new byte[((this.count - this.pos) + len)];
                        System.arraycopy(oldbuf, this.count, this.buf, 0, this.count - this.pos);
                    }
                    this.count -= this.pos;
                    this.pos = 0;
                    System.arraycopy(data, off, this.buf, this.count, len);
                    this.count += len;
                }
            }
        }
        throw new IllegalArgumentException();
    }

    public int readChecked() throws IOException {
        if (this.pos < this.count) {
            byte[] bArr = this.buf;
            int i = this.pos;
            this.pos = i + 1;
            return bArr[i] & 255;
        }
        throw new EOFException();
    }

    public int read() {
        if (this.pos >= this.count) {
            return -1;
        }
        byte[] bArr = this.buf;
        int i = this.pos;
        this.pos = i + 1;
        return bArr[i] & 255;
    }
}
