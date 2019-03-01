package es.gob.jmulticard.card;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;

public abstract class SmartCard implements Card {
    private final byte cla;
    private ApduConnection connection;

    public abstract String getCardName();

    protected ApduConnection getConnection() {
        return this.connection;
    }

    protected void setConnection(ApduConnection conn) throws ApduConnectionException {
        if (!conn.isOpen()) {
            conn.open();
        }
        this.connection = conn;
    }

    protected byte getCla() {
        return this.cla;
    }

    public SmartCard(byte c, ApduConnection conn) throws ApduConnectionException {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion con la tarjeta no puede ser nula");
        }
        this.cla = c;
        this.connection = conn;
    }
}
