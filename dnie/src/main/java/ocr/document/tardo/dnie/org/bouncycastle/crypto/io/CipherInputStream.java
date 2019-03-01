package org.bouncycastle.crypto.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.StreamCipher;

public class CipherInputStream extends FilterInputStream {
    private static final int INPUT_BUF_SIZE = 2048;
    private byte[] buf;
    private int bufOff;
    private BufferedBlockCipher bufferedBlockCipher;
    private boolean finalized;
    private byte[] inBuf;
    private int maxBuf;
    private StreamCipher streamCipher;

    public CipherInputStream(InputStream inputStream, BufferedBlockCipher bufferedBlockCipher) {
        super(inputStream);
        this.bufferedBlockCipher = bufferedBlockCipher;
        this.buf = new byte[bufferedBlockCipher.getOutputSize(2048)];
        this.inBuf = new byte[2048];
    }

    public CipherInputStream(InputStream inputStream, StreamCipher streamCipher) {
        super(inputStream);
        this.streamCipher = streamCipher;
        this.buf = new byte[2048];
        this.inBuf = new byte[2048];
    }

    private int nextChunk() throws IOException {
        int available = super.available();
        if (available <= 0) {
            available = 1;
        }
        int read = available > this.inBuf.length ? super.read(this.inBuf, 0, this.inBuf.length) : super.read(this.inBuf, 0, available);
        if (read >= 0) {
            this.bufOff = 0;
            try {
                if (this.bufferedBlockCipher != null) {
                    this.maxBuf = this.bufferedBlockCipher.processBytes(this.inBuf, 0, read, this.buf, 0);
                } else {
                    this.streamCipher.processBytes(this.inBuf, 0, read, this.buf, 0);
                    this.maxBuf = read;
                }
                if (this.maxBuf == 0) {
                    return nextChunk();
                }
            } catch (Exception e) {
                throw new IOException("error processing stream: " + e.toString());
            }
        } else if (this.finalized) {
            return -1;
        } else {
            try {
                if (this.bufferedBlockCipher != null) {
                    this.maxBuf = this.bufferedBlockCipher.doFinal(this.buf, 0);
                } else {
                    this.maxBuf = 0;
                }
                this.bufOff = 0;
                this.finalized = true;
                if (this.bufOff == this.maxBuf) {
                    return -1;
                }
            } catch (Exception e2) {
                throw new IOException("error processing stream: " + e2.toString());
            }
        }
        return this.maxBuf;
    }

    public int available() throws IOException {
        return this.maxBuf - this.bufOff;
    }

    public void close() throws IOException {
        super.close();
    }

    public boolean markSupported() {
        return false;
    }

    public int read() throws IOException {
        if (this.bufOff == this.maxBuf && nextChunk() < 0) {
            return -1;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        return bArr[i] & 255;
    }

    public int read(byte[] bArr) throws IOException {
        return read(bArr, 0, bArr.length);
    }

    public int read(byte[] bArr, int i, int i2) throws IOException {
        if (this.bufOff == this.maxBuf && nextChunk() < 0) {
            return -1;
        }
        int i3 = this.maxBuf - this.bufOff;
        if (i2 > i3) {
            System.arraycopy(this.buf, this.bufOff, bArr, i, i3);
            this.bufOff = this.maxBuf;
            return i3;
        }
        System.arraycopy(this.buf, this.bufOff, bArr, i, i2);
        this.bufOff += i2;
        return i2;
    }

    public long skip(long j) throws IOException {
        if (j <= 0) {
            return 0;
        }
        int i = this.maxBuf - this.bufOff;
        if (j > ((long) i)) {
            this.bufOff = this.maxBuf;
            return (long) i;
        }
        this.bufOff += (int) j;
        return (long) ((int) j);
    }
}
