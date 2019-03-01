package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;

public class Finished extends Message {
    private byte[] data;

    public Finished(byte[] bytes) {
        this.data = bytes;
        this.length = this.data.length;
    }

    public Finished(HandshakeIODataStream in, int length) throws IOException {
        if (length == 12 || length == 36) {
            this.data = in.read(length);
        } else {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect Finished");
        }
    }

    public void send(HandshakeIODataStream out) {
        out.write(this.data);
    }

    public int getType() {
        return 20;
    }

    public byte[] getData() {
        return this.data;
    }
}
