package es.gob.jmulticard.asn1;

public final class Asn1Exception extends Exception {
    private static final long serialVersionUID = 6806321101842954785L;

    public Asn1Exception(String message) {
        super(message);
    }

    public Asn1Exception(Throwable cause) {
        super(cause.getMessage());
    }

    public Asn1Exception(String message, Throwable cause) {
        super(message + " : " + cause.getMessage());
    }
}
