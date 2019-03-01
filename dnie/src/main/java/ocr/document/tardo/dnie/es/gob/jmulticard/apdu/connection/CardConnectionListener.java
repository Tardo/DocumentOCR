package es.gob.jmulticard.apdu.connection;

public interface CardConnectionListener {
    void cardInserted(CardConnectionEvent cardConnectionEvent);

    void cardRemoved(CardConnectionEvent cardConnectionEvent);
}
