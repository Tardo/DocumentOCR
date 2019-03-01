package custom.org.apache.harmony.xnet.provider.jsse;

import java.nio.ByteBuffer;

public class SSLEngineDataStream implements DataStream {
    private int available;
    private int consumed;
    private int limit;
    private int offset;
    private ByteBuffer[] srcs;

    protected SSLEngineDataStream() {
    }

    protected void setSourceBuffers(ByteBuffer[] srcs, int offset, int length) {
        this.srcs = srcs;
        this.offset = offset;
        this.limit = offset + length;
        this.consumed = 0;
        this.available = 0;
        for (int i = offset; i < this.limit; i++) {
            if (srcs[i] == null) {
                throw new IllegalStateException("Some of the input parameters are null");
            }
            this.available += srcs[i].remaining();
        }
    }

    public int available() {
        return this.available;
    }

    public boolean hasData() {
        return this.available > 0;
    }

    public byte[] getData(int length) {
        int len = length < this.available ? length : this.available;
        this.available -= len;
        this.consumed += len;
        byte[] res = new byte[len];
        int pos = 0;
        loop0:
        while (this.offset < this.limit) {
            while (this.srcs[this.offset].hasRemaining()) {
                int pos2 = pos + 1;
                res[pos] = this.srcs[this.offset].get();
                len--;
                if (len == 0) {
                    pos = pos2;
                    break loop0;
                }
                pos = pos2;
            }
            this.offset++;
        }
        return res;
    }

    protected int consumed() {
        return this.consumed;
    }
}
