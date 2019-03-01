package es.gob.jmulticard.jse.smartcardio;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;
import es.gob.jmulticard.apdu.iso7816four.VerifyApduCommand;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class SmartCardNFCConnection implements ApduConnection {
    static final String TAG = "NfcConnection";
    private static final byte TAG_RESPONSE_INVALID_LENGTH = (byte) 108;
    private static final byte TAG_RESPONSE_PENDING = (byte) 97;
    private static IsoDep misoDep;

    public IsoDep getIsoDep() {
        return misoDep;
    }

    public SmartCardNFCConnection() {
        misoDep = null;
    }

    public SmartCardNFCConnection(Tag tag) throws IOException {
        if (tag == null) {
            throw new IllegalArgumentException("El tag NFC no puede ser nulo");
        }
        misoDep = IsoDep.get(tag);
        misoDep.connect();
        misoDep.setTimeout(10000);
    }

    public ResponseAPDU transmit(CommandAPDU commandAPDU) {
        byte[] bResp = new byte[]{(byte) 0, (byte) 0};
        try {
            bResp = misoDep.transceive(commandAPDU.getBytes());
            if (bResp.length < 2) {
                throw new ApduConnectionException("No se ha recibido respuesta al envío del comando.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ResponseAPDU(bResp);
    }

    public ResponseApdu transmit(CommandApdu command) throws ApduConnectionException {
        if (misoDep == null) {
            throw new ApduConnectionException("No se puede transmitir sobre una conexion NFC cerrada");
        } else if (command == null) {
            throw new IllegalArgumentException("No se puede transmitir una APDU nula");
        } else {
            try {
                ResponseApdu response;
                if (command instanceof VerifyApduCommand) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] bcomm = command.getBytes();
                    byte[] bdata = command.getData();
                    baos.write(bcomm, 0, bcomm.length - 2);
                    baos.write(new byte[]{(byte) bdata.length});
                    baos.write(bdata);
                    response = new ResponseApdu(transmit(new CommandAPDU(baos.toByteArray())).getBytes());
                } else {
                    response = new ResponseApdu(transmit(new CommandAPDU(command.getBytes())).getBytes());
                }
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
            } catch (Exception e) {
                throw new ApduConnectionException("Error tratando de transmitir la APDU " + HexUtils.hexify(command.getBytes(), true) + " al lector NFC.", e);
            }
        }
    }

    public void open() throws ApduConnectionException {
        try {
            if (!misoDep.isConnected()) {
                misoDep.connect();
            }
        } catch (Exception e) {
            throw new ApduConnectionException("Error intentando abrir la comunicación NFC contra la tarjeta.", e);
        }
    }

    public void close() throws ApduConnectionException {
        closeConnection(false);
    }

    private void closeConnection(boolean resetCard) throws ApduConnectionException {
        if (misoDep != null) {
            try {
                if (misoDep.isConnected()) {
                    misoDep.close();
                }
            } catch (Exception e) {
                throw new ApduConnectionException("Error intentando cerrar el objeto de tarjeta inteligente, la conexion puede quedar abierta pero inutil", e);
            }
        }
    }

    public byte[] reset() throws ApduConnectionException {
        closeConnection(true);
        open();
        if (misoDep != null) {
            return misoDep.getHistoricalBytes();
        }
        throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta");
    }

    public void addCardConnectionListener(CardConnectionListener ccl) {
    }

    public void removeCardConnectionListener(CardConnectionListener ccl) {
    }

    public long[] getTerminals(boolean onlyWithCardPresent) throws ApduConnectionException {
        return null;
    }

    public String getTerminalInfo(int terminal) throws ApduConnectionException {
        return null;
    }

    public void setTerminal(int t) {
    }

    public boolean isOpen() {
        return misoDep.isConnected();
    }
}
