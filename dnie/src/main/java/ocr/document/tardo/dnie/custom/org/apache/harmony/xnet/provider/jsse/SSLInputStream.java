package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.io.InputStream;

public abstract class SSLInputStream extends InputStream {
    public abstract int available() throws IOException;

    public abstract int read() throws IOException;

    public long skip(long n) throws IOException {
        long skept = n;
        while (n > 0) {
            read();
            n--;
        }
        return skept;
    }

    public int readUint8() throws IOException {
        return read() & 255;
    }

    public int readUint16() throws IOException {
        return (read() << 8) | (read() & 255);
    }

    public int readUint24() throws IOException {
        return ((read() << 16) | (read() << 8)) | (read() & 255);
    }

    public long readUint32() throws IOException {
        return (long) ((((read() << 24) | (read() << 16)) | (read() << 8)) | (read() & 255));
    }

    public long readUint64() throws IOException {
        return (((((((((long) read()) << 56) | (((long) read()) << 48)) | (((long) read()) << 40)) | (((long) read()) << 32)) | ((long) (read() << 24))) | ((long) (read() << 16))) | ((long) (read() << 8))) | ((long) (read() & 255));
    }

    public byte[] read(int length) throws IOException {
        byte[] res = new byte[length];
        for (int i = 0; i < length; i++) {
            res[i] = (byte) read();
        }
        return res;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int i = 0;
        do {
            int read_b = read();
            if (read_b != -1) {
                b[off + i] = (byte) read_b;
                i++;
                if (available() == 0) {
                    break;
                }
            } else if (i == 0) {
                return -1;
            } else {
                return i;
            }
        } while (i < len);
        return i;
    }
}
