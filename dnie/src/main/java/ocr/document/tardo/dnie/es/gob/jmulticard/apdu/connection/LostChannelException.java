package es.gob.jmulticard.apdu.connection;

public class LostChannelException extends ApduConnectionException {
    private static final long serialVersionUID = -4881940145750512085L;

    public LostChannelException(String message) {
        super(message);
    }
}
