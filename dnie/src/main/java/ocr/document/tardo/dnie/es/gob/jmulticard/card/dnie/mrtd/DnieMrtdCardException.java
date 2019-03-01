package es.gob.jmulticard.card.dnie.mrtd;

import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.card.CryptoCardException;

public final class DnieMrtdCardException extends CryptoCardException {
    private static final long serialVersionUID = 5935577997660561619L;
    private final StatusWord returnCode;

    DnieMrtdCardException(String desc, StatusWord retCode) {
        super(desc);
        this.returnCode = retCode;
    }

    DnieMrtdCardException(String desc, Throwable t) {
        super(desc, t);
        this.returnCode = null;
    }

    DnieMrtdCardException(StatusWord retCode) {
        this.returnCode = retCode;
    }

    public StatusWord getStatusWord() {
        return this.returnCode;
    }
}