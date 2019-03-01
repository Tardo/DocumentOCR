package es.gob.jmulticard.apdu.connection;

public final class CardNotPresentException extends ApduConnectionException {
    private static final long serialVersionUID = 4766021408409413374L;

    public CardNotPresentException(Throwable cause) {
        super("No hay ninguna tarjeta insertada en el lector", cause);
    }
}
