package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.io.OutputStream;

public class SSLSocketOutputStream extends OutputStream {
    private byte[] bytik = new byte[1];
    private SSLSocketImpl owner;

    protected SSLSocketOutputStream(SSLSocketImpl owner) {
        this.owner = owner;
    }

    public void write(int b) throws IOException {
        this.bytik[0] = (byte) (b & 255);
        this.owner.writeAppData(this.bytik, 0, 1);
    }

    public void write(byte[] b) throws IOException {
        this.owner.writeAppData(b, 0, b.length);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        this.owner.writeAppData(b, off, len);
    }
}
