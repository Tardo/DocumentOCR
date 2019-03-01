package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;

public class ServerHelloDone extends Message {
    public ServerHelloDone(HandshakeIODataStream in, int length) throws IOException {
        if (length != 0) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect ServerHelloDone");
        }
    }

    public void send(HandshakeIODataStream out) {
    }

    public int length() {
        return 0;
    }

    public int getType() {
        return 14;
    }
}
