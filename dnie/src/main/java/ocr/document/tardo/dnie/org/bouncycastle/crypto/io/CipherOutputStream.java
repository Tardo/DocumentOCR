package org.bouncycastle.crypto.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.StreamCipher;

public class CipherOutputStream extends FilterOutputStream {
    private byte[] buf;
    private BufferedBlockCipher bufferedBlockCipher;
    private byte[] oneByte;
    private StreamCipher streamCipher;

    public CipherOutputStream(OutputStream outputStream, BufferedBlockCipher bufferedBlockCipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.bufferedBlockCipher = bufferedBlockCipher;
        this.buf = new byte[bufferedBlockCipher.getBlockSize()];
    }

    public CipherOutputStream(OutputStream outputStream, StreamCipher streamCipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.streamCipher = streamCipher;
    }

    public void close() throws IOException {
        try {
            if (this.bufferedBlockCipher != null) {
                byte[] bArr = new byte[this.bufferedBlockCipher.getOutputSize(0)];
                int doFinal = this.bufferedBlockCipher.doFinal(bArr, 0);
                if (doFinal != 0) {
                    this.out.write(bArr, 0, doFinal);
                }
            }
            flush();
            super.close();
        } catch (Exception e) {
            throw new IOException("Error closing stream: " + e.toString());
        }
    }

    public void flush() throws IOException {
        super.flush();
    }

    public void write(int i) throws IOException {
        this.oneByte[0] = (byte) i;
        if (this.bufferedBlockCipher != null) {
            int processBytes = this.bufferedBlockCipher.processBytes(this.oneByte, 0, 1, this.buf, 0);
            if (processBytes != 0) {
                this.out.write(this.buf, 0, processBytes);
                return;
            }
            return;
        }
        this.out.write(this.streamCipher.returnByte((byte) i));
    }

    public void write(byte[] bArr) throws IOException {
        write(bArr, 0, bArr.length);
    }

    public void write(byte[] bArr, int i, int i2) throws IOException {
        byte[] bArr2;
        if (this.bufferedBlockCipher != null) {
            bArr2 = new byte[this.bufferedBlockCipher.getOutputSize(i2)];
            int processBytes = this.bufferedBlockCipher.processBytes(bArr, i, i2, bArr2, 0);
            if (processBytes != 0) {
                this.out.write(bArr2, 0, processBytes);
                return;
            }
            return;
        }
        bArr2 = new byte[i2];
        this.streamCipher.processBytes(bArr, i, i2, bArr2, 0);
        this.out.write(bArr2, 0, i2);
    }
}
