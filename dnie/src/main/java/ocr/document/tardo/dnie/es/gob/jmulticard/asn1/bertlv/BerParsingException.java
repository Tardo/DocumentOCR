package es.gob.jmulticard.asn1.bertlv;

public final class BerParsingException extends RuntimeException {
    private static final long serialVersionUID = 4729535660890694828L;

    public BerParsingException(String message) {
        super(message);
    }

    public BerParsingException(Throwable cause) {
        super(cause);
    }
}
