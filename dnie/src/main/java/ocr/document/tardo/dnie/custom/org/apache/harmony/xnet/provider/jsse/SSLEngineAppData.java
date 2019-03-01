package custom.org.apache.harmony.xnet.provider.jsse;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLException;

public class SSLEngineAppData implements Appendable {
    byte[] buffer;

    protected SSLEngineAppData() {
    }

    public void append(byte[] src) {
        if (this.buffer != null) {
            throw new AlertException((byte) 80, new SSLException("Attempt to override the data"));
        }
        this.buffer = src;
    }

    protected int placeTo(ByteBuffer[] dsts, int offset, int length) {
        if (this.buffer == null) {
            return 0;
        }
        int pos = 0;
        int len = this.buffer.length;
        for (int i = offset; i < offset + length; i++) {
            int rem = dsts[i].remaining();
            if (len - pos < rem) {
                dsts[i].put(this.buffer, pos, len - pos);
                pos = len;
                break;
            }
            dsts[i].put(this.buffer, pos, rem);
            pos += rem;
        }
        if (pos != len) {
            throw new AlertException((byte) 80, new SSLException("The received application data could not be fully writteninto the destination buffers"));
        }
        this.buffer = null;
        return len;
    }
}
