package es.gob.jmulticard.asn1;

public final class Asn1SyntaxException extends Exception {
    private static final long serialVersionUID = 2189471462653074438L;

    public Asn1SyntaxException(String message) {
        super(message);
    }

    public Asn1SyntaxException(Throwable cause) {
        super(cause.getMessage());
    }

    public Asn1SyntaxException(String message, Throwable cause) {
        super(message + ": " + cause.getMessage());
    }
}
