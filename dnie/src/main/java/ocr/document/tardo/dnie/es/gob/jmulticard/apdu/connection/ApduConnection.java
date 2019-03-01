package es.gob.jmulticard.apdu.connection;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;

public interface ApduConnection {
    void addCardConnectionListener(CardConnectionListener cardConnectionListener);

    void close() throws ApduConnectionException;

    String getTerminalInfo(int i) throws ApduConnectionException;

    long[] getTerminals(boolean z) throws ApduConnectionException;

    boolean isOpen();

    void open() throws ApduConnectionException;

    void removeCardConnectionListener(CardConnectionListener cardConnectionListener);

    byte[] reset() throws ApduConnectionException;

    void setTerminal(int i);

    ResponseApdu transmit(CommandApdu commandApdu) throws ApduConnectionException;
}
