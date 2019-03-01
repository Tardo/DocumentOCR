package org.bouncycastle.crypto.tls;

public class ByteQueue {
    private static final int INITBUFSIZE = 1024;
    private int available = 0;
    private byte[] databuf = new byte[1024];
    private int skipped = 0;

    public static final int nextTwoPow(int i) {
        int i2 = (i >> 1) | i;
        i2 |= i2 >> 2;
        i2 |= i2 >> 4;
        i2 |= i2 >> 8;
        return (i2 | (i2 >> 16)) + 1;
    }

    public void addData(byte[] bArr, int i, int i2) {
        if ((this.skipped + this.available) + i2 > this.databuf.length) {
            Object obj = new byte[nextTwoPow(bArr.length)];
            System.arraycopy(this.databuf, this.skipped, obj, 0, this.available);
            this.skipped = 0;
            this.databuf = obj;
        }
        System.arraycopy(bArr, i, this.databuf, this.skipped + this.available, i2);
        this.available += i2;
    }

    public void read(byte[] bArr, int i, int i2, int i3) {
        if (this.available - i3 < i2) {
            throw new TlsRuntimeException("Not enough data to read");
        } else if (bArr.length - i < i2) {
            throw new TlsRuntimeException("Buffer size of " + bArr.length + " is too small for a read of " + i2 + " bytes");
        } else {
            System.arraycopy(this.databuf, this.skipped + i3, bArr, i, i2);
        }
    }

    public void removeData(int i) {
        if (i > this.available) {
            throw new TlsRuntimeException("Cannot remove " + i + " bytes, only got " + this.available);
        }
        this.available -= i;
        this.skipped += i;
        if (this.skipped > this.databuf.length / 2) {
            System.arraycopy(this.databuf, this.skipped, this.databuf, 0, this.available);
            this.skipped = 0;
        }
    }

    public int size() {
        return this.available;
    }
}
