package es.gob.jmulticard.jse.smartcardio;

import custom.org.apache.harmony.security.fortress.PolicyUtils;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionOpenedInExclusiveModeException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

public final class SmartcardIoConnection implements ApduConnection {
    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard");
    private static final String SCARD_W_REMOVED_CARD = "SCARD_W_REMOVED_CARD";
    private static final String SCARD_W_RESET_CARD = "SCARD_W_RESET_CARD";
    private static final byte TAG_RESPONSE_INVALID_LENGTH = (byte) 108;
    private static final byte TAG_RESPONSE_PENDING = (byte) 97;
    private CardChannel canal = null;
    private Card card = null;
    private boolean exclusive = false;
    private ConnectionProtocol protocol = ConnectionProtocol.T0;
    private int terminalNumber = 0;

    public enum ConnectionProtocol {
        T0,
        T1,
        TCL;

        public String toString() {
            switch (this) {
                case T0:
                    return "T=0";
                case T1:
                    return "T=1";
                case TCL:
                    return "T=CL";
                default:
                    return "";
            }
        }
    }

    public void addCardConnectionListener(CardConnectionListener ccl) {
        throw new UnsupportedOperationException("JSR-268 no soporta eventos de insercion o extraccion");
    }

    public void close() throws ApduConnectionException {
        closeConnection(false);
    }

    private void closeConnection(boolean resetCard) throws ApduConnectionException {
        if (this.card != null) {
            try {
                this.card.disconnect(resetCard);
                this.card = null;
            } catch (Exception e) {
                throw new ApduConnectionException("Error intentando cerrar el objeto de tarjeta inteligente, la conexion puede quedar abierta pero inutil", e);
            }
        }
        this.canal = null;
    }

    public String getTerminalInfo(int terminal) {
        LOGGER.warning("No se ha podido recuperar la informaciÃ³n del terminal");
        return null;
    }

    public long[] getTerminals(boolean onlyWithCardPresent) {
        return null;
    }

    public boolean isOpen() {
        return this.card != null;
    }

    public void open() throws ApduConnectionException {
        System.setProperty("sun.security.smartcardio.t0GetResponse", PolicyUtils.FALSE);
        System.setProperty("sun.security.smartcardio.t1GetResponse", PolicyUtils.FALSE);
        if (isExclusiveUse() && isOpen()) {
            throw new ApduConnectionOpenedInExclusiveModeException();
        }
    }

    public void removeCardConnectionListener(CardConnectionListener ccl) {
        throw new UnsupportedOperationException("JSR-268 no soporta eventos de insercion o extraccion");
    }

    public byte[] reset() throws ApduConnectionException {
        if (this.card == null) {
            open();
        }
        closeConnection(true);
        open();
        close();
        open();
        if (this.card != null) {
            return this.card.getATR().getBytes();
        }
        throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta");
    }

    public void setExclusiveUse(boolean ex) {
        if (this.card == null) {
            this.exclusive = ex;
        } else {
            LOGGER.warning("No se puede cambiar el modo de acceso a la tarjeta con la conexion abierta, se mantendra el modo EXCLUSIVE=" + Boolean.toString(this.exclusive));
        }
    }

    public void setProtocol(ConnectionProtocol p) {
        if (p == null) {
            LOGGER.warning("El protocolo de conexion no puede ser nulo, se usara T=0");
            this.protocol = ConnectionProtocol.T0;
            return;
        }
        this.protocol = p;
    }

    public void setTerminal(int terminalN) {
        if (this.terminalNumber != terminalN) {
            boolean wasOpened = isOpen();
            if (wasOpened) {
                try {
                    close();
                } catch (Exception e) {
                    LOGGER.warning("Error intentando cerrar la conexion con el lector: " + e);
                }
                this.terminalNumber = terminalN;
                if (wasOpened) {
                    try {
                        open();
                    } catch (Exception e2) {
                        LOGGER.warning("Error intentando abrir la conexion con el lector: " + e2);
                    }
                }
            }
        }
    }

    public ResponseApdu transmit(CommandApdu command) throws ApduConnectionException {
        CardException e;
        ResponseApdu responseApdu;
        Throwable t;
        Exception e2;
        if (this.canal == null) {
            throw new ApduConnectionException("No se puede transmitir sobre una conexion cerrada");
        } else if (command == null) {
            throw new IllegalArgumentException("No se puede transmitir una APDU nula");
        } else {
            try {
                ResponseApdu response = new ResponseApdu(this.canal.transmit(new CommandAPDU(command.getBytes())).getBytes());
                try {
                    if (response.getStatusWord().getMsb() == TAG_RESPONSE_PENDING) {
                        if (response.getData().length <= 0) {
                            return transmit(new GetResponseApduCommand((byte) 0, response.getStatusWord().getLsb()));
                        }
                        byte[] data = response.getData();
                        byte[] additionalData = transmit(new GetResponseApduCommand((byte) 0, response.getStatusWord().getLsb())).getBytes();
                        byte[] fullResponse = new byte[(data.length + additionalData.length)];
                        System.arraycopy(data, 0, fullResponse, 0, data.length);
                        System.arraycopy(additionalData, 0, fullResponse, data.length, additionalData.length);
                        return new ResponseApdu(fullResponse);
                    } else if (response.getStatusWord().getMsb() != TAG_RESPONSE_INVALID_LENGTH || command.getCla() != (byte) 0) {
                        return response;
                    } else {
                        command.setLe(response.getStatusWord().getLsb());
                        return transmit(command);
                    }
                } catch (CardException e3) {
                    e = e3;
                    responseApdu = response;
                    t = e.getCause();
                    if (t == null && SCARD_W_RESET_CARD.equals(t.getMessage())) {
                        throw new LostChannelException(t.getMessage());
                    }
                    throw new ApduConnectionException("Error de comunicacion con la tarjeta tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector " + Integer.toString(this.terminalNumber) + " en modo EXCLUSIVE=" + Boolean.toString(this.exclusive) + " con el protocolo " + this.protocol.toString(), e);
                } catch (Exception e4) {
                    e2 = e4;
                    responseApdu = response;
                    throw new ApduConnectionException("Error tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector " + Integer.toString(this.terminalNumber) + " en modo EXCLUSIVE=" + Boolean.toString(this.exclusive) + " con el protocolo " + this.protocol.toString(), e2);
                }
            } catch (CardException e5) {
                e = e5;
                t = e.getCause();
                if (t == null) {
                }
                throw new ApduConnectionException("Error de comunicacion con la tarjeta tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector " + Integer.toString(this.terminalNumber) + " en modo EXCLUSIVE=" + Boolean.toString(this.exclusive) + " con el protocolo " + this.protocol.toString(), e);
            } catch (Exception e6) {
                e2 = e6;
                throw new ApduConnectionException("Error tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector " + Integer.toString(this.terminalNumber) + " en modo EXCLUSIVE=" + Boolean.toString(this.exclusive) + " con el protocolo " + this.protocol.toString(), e2);
            }
        }
    }

    public ConnectionProtocol getProtocol() {
        return this.protocol;
    }

    public boolean isExclusiveUse() {
        return this.exclusive;
    }
}
