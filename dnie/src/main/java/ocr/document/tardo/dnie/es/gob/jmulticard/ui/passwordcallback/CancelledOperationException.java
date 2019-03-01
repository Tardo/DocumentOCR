package es.gob.jmulticard.ui.passwordcallback;

public final class CancelledOperationException extends RuntimeException {
    private static final long serialVersionUID = 4447842480432712246L;

    public CancelledOperationException(String msg) {
        super(msg);
    }
}
