package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.apdu.connection.ApduConnectionException;

public class SecureChannelException extends ApduConnectionException {
    private static final long serialVersionUID = 3618976402641614649L;

    public SecureChannelException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public SecureChannelException(String msg) {
        super(msg);
    }
}
