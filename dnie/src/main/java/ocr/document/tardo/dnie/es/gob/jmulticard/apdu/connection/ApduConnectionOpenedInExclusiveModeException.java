package es.gob.jmulticard.apdu.connection;

public final class ApduConnectionOpenedInExclusiveModeException extends ApduConnectionException {
    private static final long serialVersionUID = 4324304100060050246L;

    public ApduConnectionOpenedInExclusiveModeException() {
        super("No se ha podido abrir la conexion exclusiva con el lector de tarjetas");
    }
}
