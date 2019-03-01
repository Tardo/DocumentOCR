package es.gob.jmulticard.apdu.connection;

public class NoReadersFoundException extends ApduConnectionException {
    private static final long serialVersionUID = -7828305035163301527L;

    public NoReadersFoundException() {
        super("No se detectaron lectores de tarjetas en el sistema");
    }
}
