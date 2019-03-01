package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.nio.ByteBuffer;

public class SSLBufferedInput extends SSLInputStream {
    private int bytik;
    private int consumed = 0;
    private ByteBuffer in;

    protected SSLBufferedInput() {
    }

    protected void setSourceBuffer(ByteBuffer in) {
        this.consumed = 0;
        this.in = in;
    }

    public int available() throws IOException {
        return this.in.remaining();
    }

    protected int consumed() {
        return this.consumed;
    }

    public int read() throws IOException {
        this.bytik = this.in.get() & 255;
        this.consumed++;
        return this.bytik;
    }
}
