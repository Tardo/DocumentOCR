package custom.org.apache.harmony.xnet.provider.jsse;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

public abstract class Message {
    protected int length;

    abstract int getType();

    abstract void send(HandshakeIODataStream handshakeIODataStream);

    public int length() {
        return this.length;
    }

    protected void fatalAlert(byte description, String reason) {
        throw new AlertException(description, new SSLHandshakeException(reason));
    }

    protected void fatalAlert(byte description, String reason, Throwable cause) {
        throw new AlertException(description, new SSLException(reason, cause));
    }
}
