package custom.javax.net.ssl;

public class SSLEngineResult {
    private final int bytesConsumed;
    private final int bytesProduced;
    private final HandshakeStatus handshakeStatus;
    private final Status status;

    public enum HandshakeStatus {
        NOT_HANDSHAKING,
        FINISHED,
        NEED_TASK,
        NEED_WRAP,
        NEED_UNWRAP
    }

    public enum Status {
        BUFFER_OVERFLOW,
        BUFFER_UNDERFLOW,
        CLOSED,
        OK
    }

    public SSLEngineResult(Status status, HandshakeStatus handshakeStatus, int bytesConsumed, int bytesProduced) {
        if (status == null) {
            throw new IllegalArgumentException("status is null");
        } else if (handshakeStatus == null) {
            throw new IllegalArgumentException("handshakeStatus is null");
        } else if (bytesConsumed < 0) {
            throw new IllegalArgumentException("bytesConsumed is negative");
        } else if (bytesProduced < 0) {
            throw new IllegalArgumentException("bytesProduced is negative");
        } else {
            this.status = status;
            this.handshakeStatus = handshakeStatus;
            this.bytesConsumed = bytesConsumed;
            this.bytesProduced = bytesProduced;
        }
    }

    public final Status getStatus() {
        return this.status;
    }

    public final HandshakeStatus getHandshakeStatus() {
        return this.handshakeStatus;
    }

    public final int bytesConsumed() {
        return this.bytesConsumed;
    }

    public final int bytesProduced() {
        return this.bytesProduced;
    }

    public String toString() {
        return "SSLEngineReport: Status = " + this.status + "  HandshakeStatus = " + this.handshakeStatus + "\n                 bytesConsumed = " + this.bytesConsumed + " bytesProduced = " + this.bytesProduced;
    }
}
