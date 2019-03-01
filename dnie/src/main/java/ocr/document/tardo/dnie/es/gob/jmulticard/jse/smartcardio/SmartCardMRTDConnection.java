package es.gob.jmulticard.jse.smartcardio;

import android.nfc.tech.IsoDep;
import android.util.Log;
import de.tsenger.androsmex.IsoDepCardHandler;
import de.tsenger.androsmex.asn1.PaceInfo;
import de.tsenger.androsmex.asn1.SecurityInfos;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.FileAccess;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import de.tsenger.androsmex.pace.PaceException;
import de.tsenger.androsmex.pace.PaceOperator;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ReadBinaryApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.asn1.TlvException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SmartCardMRTDConnection implements ApduConnection {
    private static final byte[] ID_FILE_3F00 = new byte[]{(byte) 0, (byte) 0};
    private static final byte[] ID_FILE_3F01 = new byte[]{(byte) 63, (byte) 1};
    private static final byte[] ID_FILE_DG1 = new byte[]{(byte) 1, (byte) 1};
    private static final byte[] ID_FILE_DG11 = new byte[]{(byte) 1, (byte) 11};
    private static final byte[] ID_FILE_DG13 = new byte[]{(byte) 1, (byte) 13};
    private static final byte[] ID_FILE_DG2 = new byte[]{(byte) 1, (byte) 2};
    private static final byte[] ID_FILE_DG7 = new byte[]{(byte) 1, (byte) 7};
    private static final byte[] ID_FILE_EFCOM = new byte[]{(byte) 1, (byte) 30};
    private static final String MASTER_FILE_NAME = "Master.File";
    static final String TAG = "SmartCardMRTDConnection";
    private static final byte TAG_RESPONSE_INVALID_LENGTH = (byte) 108;
    private static final byte TAG_RESPONSE_PENDING = (byte) 97;
    private static IsoDep misoDep;
    long endtime = 0;
    public IsoDepCardHandler idch = null;
    private String myCanNumber;
    PaceOperator ptag = null;
    long starttime = 0;

    public IsoDep getIsoDep() {
        return misoDep;
    }

    public SmartCardMRTDConnection() {
        misoDep = null;
    }

    public SmartCardMRTDConnection(IsoDep isoDep, String pace) throws IOException {
        if (isoDep == null) {
            throw new IllegalArgumentException("El tag NFC no puede ser nulo");
        }
        misoDep = isoDep;
        misoDep.close();
        if (!misoDep.isConnected()) {
            misoDep.connect();
            misoDep.setTimeout(10000);
        }
        this.idch = new IsoDepCardHandler(misoDep);
        this.myCanNumber = pace;
        try {
            performPACEwithCAN(this.myCanNumber);
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
    }

    public EF_COM readEFCOM() throws IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_EFCOM))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag == (byte) 96) {
                    int tlvTotalLen = 2;
                    int size = inStr.read() & 255;
                    if (size == 128) {
                        if ((tag & 32) == 0) {
                            throw new IOException("Longitud del TLV invalida");
                        }
                    } else if (size >= 128) {
                        int sizeLen = size - 128;
                        if (sizeLen > 3) {
                            throw new IOException("TLV demasiado largo");
                        }
                        size = 0;
                        while (sizeLen > 0) {
                            size = (size << 8) + (inStr.read() & 255);
                            sizeLen--;
                            tlvTotalLen++;
                        }
                    }
                    size += tlvTotalLen;
                    int dataRead = 0;
                    while (dataRead < size) {
                        ResponseApdu readResponse;
                        int left = size - dataRead;
                        if (left < 239) {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                            dataRead += left;
                            off += left;
                        } else {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                            dataRead += 239;
                            off += 239;
                        }
                        out.write(readResponse.getData());
                        msbOffset = (byte) (off >> 8);
                        lsbOffset = (byte) (off & 255);
                    }
                }
            }
            return new EF_COM(out.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("Error durante lectura EF_COM.");
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Operación errónea durante lectura EF_COM.");
        }
    }

    public DG1_Dnie readDG1() throws IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_DG1))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag != (byte) 97) {
                    throw new TlvException("Error de datos en la lectura del DG1");
                }
                int tlvTotalLen = 2;
                int size = inStr.read() & 255;
                if (size == 128) {
                    if ((tag & 32) == 0) {
                        throw new IOException("Longitud del TLV invalida");
                    }
                } else if (size >= 128) {
                    int sizeLen = size - 128;
                    if (sizeLen > 3) {
                        throw new IOException("TLV demasiado largo");
                    }
                    size = 0;
                    while (sizeLen > 0) {
                        size = (size << 8) + (inStr.read() & 255);
                        sizeLen--;
                        tlvTotalLen++;
                    }
                }
                size += tlvTotalLen;
                int dataRead = 0;
                while (dataRead < size) {
                    ResponseApdu readResponse;
                    int left = size - dataRead;
                    if (left < 239) {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                        dataRead += left;
                        off += left;
                    } else {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                        dataRead += 239;
                        off += 239;
                    }
                    out.write(readResponse.getData());
                    msbOffset = (byte) (off >> 8);
                    lsbOffset = (byte) (off & 255);
                }
            }
            return new DG1_Dnie(out.toByteArray());
        } catch (TlvException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Error durante lectura DG1.");
        } catch (Exception e22) {
            e22.printStackTrace();
            throw new IOException("Operación errónea durante lectura DG1.");
        }
    }

    public DG11 readDG11() throws TlvException, IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_DG11))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag != (byte) 107) {
                    throw new TlvException("Error de datos en la lectura del DG11");
                }
                int tlvTotalLen = 2;
                int size = inStr.read() & 255;
                if (size == 128) {
                    if ((tag & 32) == 0) {
                        throw new IOException("Longitud del TLV invalida");
                    }
                } else if (size >= 128) {
                    int sizeLen = size - 128;
                    if (sizeLen > 3) {
                        throw new IOException("TLV demasiado largo");
                    }
                    size = 0;
                    while (sizeLen > 0) {
                        size = (size << 8) + (inStr.read() & 255);
                        sizeLen--;
                        tlvTotalLen++;
                    }
                }
                size += tlvTotalLen;
                int dataRead = 0;
                while (dataRead < size) {
                    ResponseApdu readResponse;
                    int left = size - dataRead;
                    if (left < 239) {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                        dataRead += left;
                        off += left;
                    } else {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                        dataRead += 239;
                        off += 239;
                    }
                    out.write(readResponse.getData());
                    msbOffset = (byte) (off >> 8);
                    lsbOffset = (byte) (off & 255);
                }
            }
            return new DG11(out.toByteArray());
        } catch (TlvException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Error durante lectura DG11.");
        } catch (Exception e22) {
            e22.printStackTrace();
            throw new IOException("Operación errónea durante lectura DG11.");
        }
    }

    public DG13 readDG13() throws TlvException, IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_DG13))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag != (byte) 109) {
                    throw new TlvException("Error de datos en la lectura del DG13");
                }
                int tlvTotalLen = 2;
                int size = inStr.read() & 255;
                if (size == 128) {
                    if ((tag & 32) == 0) {
                        throw new IOException("Longitud del TLV invalida");
                    }
                } else if (size >= 128) {
                    int sizeLen = size - 128;
                    if (sizeLen > 3) {
                        throw new IOException("TLV demasiado largo");
                    }
                    size = 0;
                    while (sizeLen > 0) {
                        size = (size << 8) + (inStr.read() & 255);
                        sizeLen--;
                        tlvTotalLen++;
                    }
                }
                size += tlvTotalLen;
                int dataRead = 0;
                while (dataRead < size) {
                    ResponseApdu readResponse;
                    int left = size - dataRead;
                    if (left < 239) {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                        dataRead += left;
                        off += left;
                    } else {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                        dataRead += 239;
                        off += 239;
                    }
                    out.write(readResponse.getData());
                    msbOffset = (byte) (off >> 8);
                    lsbOffset = (byte) (off & 255);
                }
            }
            return new DG13(out.toByteArray());
        } catch (TlvException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Error durante lectura DG13.");
        } catch (Exception e22) {
            e22.printStackTrace();
            throw new IOException("Operación errónea durante lectura DG13.");
        }
    }

    public DG2 readDG2() throws IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_DG2))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag != (byte) 117) {
                    throw new TlvException("Error de datos en la lectura del DG2");
                }
                int tlvTotalLen = 2;
                int size = inStr.read() & 255;
                if (size == 128) {
                    if ((tag & 32) == 0) {
                        throw new IOException("Longitud del TLV invalida");
                    }
                } else if (size >= 128) {
                    int sizeLen = size - 128;
                    if (sizeLen > 3) {
                        throw new IOException("TLV demasiado largo");
                    }
                    size = 0;
                    while (sizeLen > 0) {
                        size = (size << 8) + (inStr.read() & 255);
                        sizeLen--;
                        tlvTotalLen++;
                    }
                }
                size += tlvTotalLen;
                int dataRead = 0;
                while (dataRead < size) {
                    ResponseApdu readResponse;
                    int left = size - dataRead;
                    if (left < 239) {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                        dataRead += left;
                        off += left;
                    } else {
                        readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                        dataRead += 239;
                        off += 239;
                    }
                    out.write(readResponse.getData());
                    msbOffset = (byte) (off >> 8);
                    lsbOffset = (byte) (off & 255);
                }
            }
            return new DG2(out.toByteArray());
        } catch (TlvException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Error durante lectura DG2.");
        } catch (Exception e22) {
            e22.printStackTrace();
            throw new IOException("Operación errónea durante lectura DG2.");
        }
    }

    public DG7 readDG7() throws IOException {
        try {
            ResponseApdu myResponse = transmit(new SelectDfByNameApduCommand((byte) 0, MASTER_FILE_NAME.getBytes()));
            myResponse = transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_3F01));
            int fileLen = new SelectFileApduResponse(transmit(new SelectFileByIdApduCommand((byte) 0, ID_FILE_DG7))).getFileLength();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int off = 0;
            byte msbOffset = (byte) 0;
            byte lsbOffset = (byte) 0;
            while (off < fileLen) {
                ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
                byte tag = (byte) inStr.read();
                if (tag == (byte) 101 || tag == (byte) 103) {
                    int tlvTotalLen = 2;
                    int size = inStr.read() & 255;
                    if (size == 128) {
                        if ((tag & 32) == 0) {
                            throw new IOException("Longitud del TLV invalida");
                        }
                    } else if (size >= 128) {
                        int sizeLen = size - 128;
                        if (sizeLen > 3) {
                            throw new IOException("TLV demasiado largo");
                        }
                        size = 0;
                        while (sizeLen > 0) {
                            size = (size << 8) + (inStr.read() & 255);
                            sizeLen--;
                            tlvTotalLen++;
                        }
                    }
                    size += tlvTotalLen;
                    int dataRead = 0;
                    while (dataRead < size) {
                        ResponseApdu readResponse;
                        int left = size - dataRead;
                        if (left < 239) {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                            dataRead += left;
                            off += left;
                        } else {
                            readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                            dataRead += 239;
                            off += 239;
                        }
                        out.write(readResponse.getData());
                        msbOffset = (byte) (off >> 8);
                        lsbOffset = (byte) (off & 255);
                    }
                } else {
                    throw new TlvException("Error de datos en la lectura del DG7");
                }
            }
            return new DG7(out.toByteArray());
        } catch (TlvException e) {
            e.printStackTrace();
            throw e;
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new IOException("Error durante lectura DG2.");
        } catch (Exception e22) {
            e22.printStackTrace();
            throw new IOException("Operación errónea durante lectura DG2.");
        }
    }

    private ResponseApdu readBinary(byte msbOffset, byte lsbOffset, byte readLength) throws ApduConnectionException {
        return transmit(new ReadBinaryApduCommand((byte) 0, msbOffset, lsbOffset, readLength));
    }

    private SecurityInfos getSecurityInfosFromCardAccess() {
        Exception e1;
        SecurityInfos si = null;
        try {
            byte[] efcaBytes = new FileAccess(this.idch).getFile(new byte[]{(byte) 1, (byte) 28});
            SecurityInfos si2 = new SecurityInfos();
            try {
                si2.decode(efcaBytes);
                return si2;
            } catch (Exception e) {
                e1 = e;
                si = si2;
                Log.e(TAG, "getSecurityInfosFromCardAccess() throws exception", e1);
                return si;
            }
        } catch (Exception e2) {
            e1 = e2;
            Log.e(TAG, "getSecurityInfosFromCardAccess() throws exception", e1);
            return si;
        }
    }

    public void performPACEwithCAN(String can) throws PaceException, IOException {
        try {
            this.starttime = System.currentTimeMillis();
            SecurityInfos si = getSecurityInfosFromCardAccess();
            this.ptag = new PaceOperator(this.idch);
            this.ptag.setAuthTemplate((PaceInfo) si.getPaceInfoList().get(0), can);
            this.ptag.performPACE();
            this.endtime = System.currentTimeMillis();
        } catch (IOException e) {
            Log.e(TAG, "IOException en canal PACE");
            throw new IOException("Se ha perdido la conexión con el DNIe.");
        } catch (SecureMessagingException e2) {
            Log.e(TAG, "SecureMessagingException en canal PACE");
            throw new IOException("Error en la securización de comandos al montar el canal PACE.");
        } catch (PaceException e3) {
            Log.e(TAG, "PaceException en canal PACE");
            if (e3.getMessage().contains("69 88")) {
                throw new IOException("Error al montar canal PACE. CAN incorrecto.");
            }
            throw new IOException("Error al montar canal PACE.");
        } catch (InterruptedException e4) {
            e4.printStackTrace();
            throw new IOException("Operación interrumpida montando canal PACE.");
        } catch (Throwable th) {
            this.endtime = System.currentTimeMillis();
        }
    }

    public ResponseAPDU transmit(CommandAPDU commandAPDU) throws LostChannelException, IOException, SecureMessagingException {
        return this.idch.transceive(commandAPDU);
    }

    public ResponseApdu transmit(CommandApdu command) throws ApduConnectionException {
        if (misoDep == null) {
            throw new ApduConnectionException("No se puede transmitir sobre una conexion NFC cerrada");
        } else if (command == null) {
            throw new IllegalArgumentException("No se puede transmitir una APDU nula");
        } else {
            try {
                ResponseApdu response = new ResponseApdu(transmit(new CommandAPDU(command.getBytes())).getBytes());
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
            } catch (LostChannelException e) {
                throw new LostChannelException(e.getMessage());
            } catch (Exception e2) {
                throw new ApduConnectionException("Error tratando de transmitir APDU " + HexUtils.hexify(command.getBytes(), true).substring(0, 15) + "(...) al lector NFC.", e2);
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
    }

    public byte[] reset() throws ApduConnectionException {
        closeConnection(true);
        open();
        if (misoDep == null) {
            throw new ApduConnectionException("Error indefinido reiniciando la conexion con la tarjeta");
        } else if (misoDep.getHistoricalBytes() != null) {
            return misoDep.getHistoricalBytes();
        } else {
            return misoDep.getHiLayerResponse();
        }
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
