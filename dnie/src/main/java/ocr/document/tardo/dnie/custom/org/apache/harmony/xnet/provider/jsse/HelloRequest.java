package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;

public class HelloRequest extends Message {
    public HelloRequest(HandshakeIODataStream in, int length) throws IOException {
        if (length != 0) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect HelloRequest");
        }
    }

    public void send(HandshakeIODataStream out) {
    }

    public int length() {
        return 0;
    }

    public int getType() {
        return 0;
    }
}
