package es.inteco.labs.android.exception;

public final class DialogInterruptedException extends RuntimeException {
    private static final long serialVersionUID = 6642546236712253221L;

    public DialogInterruptedException(Exception excp) {
        super(excp);
    }
}
