package es.gob.jmulticard.card;

public class CryptoCardException extends CardException {
    private static final long serialVersionUID = -3133117372570125570L;

    public CryptoCardException(String msg) {
        super(msg);
    }

    public CryptoCardException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
