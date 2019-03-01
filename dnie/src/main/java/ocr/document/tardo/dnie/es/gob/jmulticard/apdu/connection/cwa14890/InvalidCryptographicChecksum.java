package es.gob.jmulticard.apdu.connection.cwa14890;

public final class InvalidCryptographicChecksum extends SecurityException {
    private static final long serialVersionUID = -366110067889217051L;

    InvalidCryptographicChecksum() {
        super("Checksum criptografico invalido (APDU respuesta = 6688)");
    }
}
