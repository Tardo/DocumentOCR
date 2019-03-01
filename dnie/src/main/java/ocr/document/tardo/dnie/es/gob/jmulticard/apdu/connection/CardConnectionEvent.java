package es.gob.jmulticard.apdu.connection;

import java.util.EventObject;

public final class CardConnectionEvent extends EventObject {
    private static final long serialVersionUID = 5904349664169930807L;

    public CardConnectionEvent(ApduConnection conn) {
        super(conn);
    }
}
