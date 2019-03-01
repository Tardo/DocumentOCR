package custom.org.apache.harmony.xnet.provider.jsse;

import javax.net.ssl.SSLException;

public class AlertException extends RuntimeException {
    private static final long serialVersionUID = -4448327177165687581L;
    private final byte description;
    private final SSLException reason;

    protected AlertException(byte description, SSLException reason) {
        super(reason);
        this.reason = reason;
        this.description = description;
    }

    protected SSLException getReason() {
        return this.reason;
    }

    protected byte getDescriptionCode() {
        return this.description;
    }
}
