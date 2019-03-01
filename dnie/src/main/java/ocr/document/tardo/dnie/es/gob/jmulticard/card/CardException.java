package es.gob.jmulticard.card;

import java.io.IOException;

public abstract class CardException extends IOException {
    private static final long serialVersionUID = -3054749595177932903L;

    protected CardException(String description) {
        super(description);
    }

    protected CardException() {
    }

    protected CardException(String description, Throwable cause) {
        super(description + ": " + cause.getMessage());
    }
}
