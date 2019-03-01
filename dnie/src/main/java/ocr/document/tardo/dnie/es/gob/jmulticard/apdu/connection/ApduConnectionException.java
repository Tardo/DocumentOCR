package es.gob.jmulticard.apdu.connection;

import java.io.IOException;

public class ApduConnectionException extends IOException {
    private static final long serialVersionUID = 8002087406820820877L;

    public ApduConnectionException(String message, Throwable cause) {
        super(message + ": " + cause.getMessage());
        initCause(cause);
    }

    public ApduConnectionException(String message) {
        super(message);
    }
}
