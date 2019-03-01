package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.card.CardException;

public final class BurnedDnieCardException extends CardException {
    private static final long serialVersionUID = -3337211407421513080L;

    public BurnedDnieCardException() {
        super("Se encontro un DNIe, pero con la memoria volatil borrada (codigo 6581)");
    }
}
