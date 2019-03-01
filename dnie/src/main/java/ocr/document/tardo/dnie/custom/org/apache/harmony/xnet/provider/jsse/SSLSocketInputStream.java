package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.io.InputStream;
import javax.net.ssl.SSLException;

public final class SSLSocketInputStream extends InputStream {
    private byte[] buffer = new byte[this.size];
    protected Adapter dataPoint = new Adapter();
    private int end;
    private boolean end_reached = false;
    private final SSLSocketImpl owner;
    private int pos;
    private int size = 16384;

    private class Adapter implements Appendable {
        private Adapter() {
        }

        public void append(byte[] src) {
            int length = src.length;
            if (SSLSocketInputStream.this.size - (SSLSocketInputStream.this.end - SSLSocketInputStream.this.pos) < length) {
                throw new AlertException((byte) 80, new SSLException("Could not accept income app data."));
            }
            if (SSLSocketInputStream.this.end + length > SSLSocketInputStream.this.size) {
                System.arraycopy(SSLSocketInputStream.this.buffer, SSLSocketInputStream.this.pos, SSLSocketInputStream.this.buffer, 0, SSLSocketInputStream.this.end - SSLSocketInputStream.this.pos);
                SSLSocketInputStream.access$220(SSLSocketInputStream.this, SSLSocketInputStream.this.pos);
                SSLSocketInputStream.this.pos = 0;
            }
            System.arraycopy(src, 0, SSLSocketInputStream.this.buffer, SSLSocketInputStream.this.end, length);
            SSLSocketInputStream.this.end = SSLSocketInputStream.this.end + length;
        }
    }

    static /* synthetic */ int access$220(SSLSocketInputStream x0, int x1) {
        int i = x0.end - x1;
        x0.end = i;
        return i;
    }

    protected SSLSocketInputStream(SSLSocketImpl owner) {
        this.owner = owner;
    }

    protected void setEnd() {
        this.end_reached = true;
    }

    public int available() throws IOException {
        return this.end - this.pos;
    }

    public void close() throws IOException {
        this.buffer = null;
    }

    public int read() throws IOException {
        if (this.buffer == null) {
            throw new IOException("Stream was closed.");
        }
        while (this.pos == this.end) {
            if (this.end_reached) {
                return -1;
            }
            this.owner.needAppData();
        }
        byte[] bArr = this.buffer;
        int i = this.pos;
        this.pos = i + 1;
        return bArr[i] & 255;
    }

    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
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

    public long skip(long n) throws IOException {
        long i = 0;
        int av = available();
        if (((long) av) < n) {
            n = (long) av;
        }
        while (i < n && read() != -1) {
            i++;
        }
        return i;
    }
}
