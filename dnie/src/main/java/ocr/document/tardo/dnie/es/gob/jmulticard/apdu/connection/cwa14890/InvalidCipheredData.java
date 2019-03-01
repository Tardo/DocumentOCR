package es.gob.jmulticard.apdu.connection.cwa14890;

public final class InvalidCipheredData extends SecurityException {
    private static final long serialVersionUID = -366110067889217051L;

    InvalidCipheredData() {
        super("Datos cifrados incorrectos (APDU respuesta = 6988)");
    }
}
