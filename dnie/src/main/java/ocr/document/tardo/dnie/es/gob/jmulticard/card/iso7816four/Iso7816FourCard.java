package es.gob.jmulticard.card.iso7816four;

import android.util.Log;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneConnection;
import es.gob.jmulticard.apdu.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.apdu.iso7816four.GetChallengeApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetVerificationKeyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ReadBinaryApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.apdu.iso7816four.VerifyApduCommand;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.SmartCard;
import es.gob.jmulticard.jse.smartcardio.SmartCardMRTDConnection;
import es.gob.jmulticard.jse.smartcardio.SmartCardNFCConnection;
import es.gob.jmulticard.ui.passwordcallback.gui.DialogBuilder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.security.auth.callback.PasswordCallback;

public abstract class Iso7816FourCard extends SmartCard {
    private static final byte ERROR_PIN_SW1 = (byte) 99;

    protected abstract void selectMasterFile() throws ApduConnectionException, FileNotFoundException;

    public Iso7816FourCard(byte c, ApduConnection conn) throws ApduConnectionException {
        super(c, conn);
    }

    public Iso7816FourCard(byte c, SmartCardNFCConnection conn) throws ApduConnectionException {
        super(c, conn);
    }

    private ResponseApdu readBinary(byte msbOffset, byte lsbOffset, byte readLength) throws ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new ReadBinaryApduCommand(getCla(), msbOffset, lsbOffset, readLength));
        if (res.isOk()) {
            return res;
        }
        throw new ApduConnectionException("Respuesta invalida en la lectura de binario con el codigo: " + res.getStatusWord());
    }

    public byte[] readBinaryComplete(int len) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int off = 0; off < len; off += 239) {
            ResponseApdu readResponse;
            byte msbOffset = (byte) (off >> 8);
            byte lsbOffset = (byte) (off & 255);
            int left = len - off;
            if (left < 239) {
                readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
            } else {
                readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
            }
            if (!readResponse.isOk()) {
                return readResponse.getStatusWord().getBytes();
            }
            out.write(readResponse.getData());
        }
        return out.toByteArray();
    }

    public byte[] readBinaryDataTLV(int len) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        byte msbOffset = (byte) 0;
        byte lsbOffset = (byte) 0;
        while (off < len) {
            ByteArrayInputStream inStr = new ByteArrayInputStream(readBinary(msbOffset, lsbOffset, (byte) 4).getData());
            byte tag = (byte) inStr.read();
            if (tag != (byte) 48) {
                break;
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
                if (!readResponse.isOk()) {
                    return readResponse.getStatusWord().getBytes();
                }
                out.write(readResponse.getData());
                msbOffset = (byte) (off >> 8);
                lsbOffset = (byte) (off & 255);
            }
        }
        return out.toByteArray();
    }

    public byte[] readBinaryDataCompressed(int len) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        byte msbOffset = (byte) 0;
        ResponseApdu readResponse = readBinary((byte) 0, (byte) 0, (byte) 4);
        byte lsbOffset = (byte) 0;
        byte[] comLen = readBinary((byte) 0, (byte) 4, (byte) 4).getData();
        int iTotalLen = ((((comLen[0] & 255) | ((comLen[1] & 255) << 8)) | ((comLen[2] & 255) << 16)) | ((comLen[3] & 255) << 24)) + 8;
        int dataRead = 0;
        while (dataRead < iTotalLen && iTotalLen < len) {
            int left = iTotalLen - dataRead;
            if (left < 239) {
                readResponse = readBinary(msbOffset, lsbOffset, (byte) left);
                dataRead += left;
                off += left;
            } else {
                readResponse = readBinary(msbOffset, lsbOffset, (byte) -17);
                dataRead += 239;
                off += 239;
            }
            if (!readResponse.isOk()) {
                return readResponse.getStatusWord().getBytes();
            }
            out.write(readResponse.getData());
            msbOffset = (byte) (off >> 8);
            lsbOffset = (byte) (off & 255);
        }
        return out.toByteArray();
    }

    public void selectFileByName(String name) throws ApduConnectionException, FileNotFoundException {
        ResponseApdu response = getConnection().transmit(new SelectDfByNameApduCommand(getCla(), name.getBytes()));
        if (!response.isOk() && HexUtils.arrayEquals(response.getBytes(), new byte[]{(byte) 106, (byte) -126})) {
            throw new FileNotFoundException(name);
        }
    }

    public int selectFileById(byte[] id) throws ApduConnectionException, Iso7816FourCardException {
        ResponseApdu res = getConnection().transmit(new SelectFileByIdApduCommand(getCla(), id));
        if (HexUtils.arrayEquals(res.getBytes(), new byte[]{(byte) 106, (byte) -126})) {
            throw new FileNotFoundException(id);
        }
        SelectFileApduResponse response = new SelectFileApduResponse(res);
        if (response.isOk()) {
            return response.getFileLength();
        }
        StatusWord sw = response.getStatusWord();
        if (sw.equals(new StatusWord((byte) 106, (byte) -126))) {
            throw new FileNotFoundException(id);
        }
        throw new Iso7816FourCardException(sw);
    }

    public byte[] selectFileByIdAndRead(byte[] id) throws Iso7816FourCardException, IOException {
        return readBinaryDataTLV(selectFileById(id));
    }

    public int selectFileByLocation(Location location) throws ApduConnectionException, Iso7816FourCardException {
        int fileLength = 0;
        selectMasterFile();
        for (Location loc = location; loc != null; loc = loc.getChild()) {
            fileLength = selectFileById(loc.getFile());
        }
        return fileLength;
    }

    public byte[] selectFileByLocationAndRead(Location location) throws IOException, Iso7816FourCardException {
        return readBinaryDataTLV(selectFileByLocation(location));
    }

    public byte[] selectCompressedFileByLocationAndRead(Location location) throws IOException, Iso7816FourCardException {
        return readBinaryDataCompressed(selectFileByLocation(location));
    }

    public void setPublicKeyToVerification(byte[] refPublicKey) throws SecureChannelException, ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new MseSetVerificationKeyApduCommand((byte) 0, refPublicKey));
        if (!res.isOk()) {
            throw new SecureChannelException("Error al seleccionar una clave publica para verificacion. Se obtuvo el error: " + HexUtils.hexify(res.getBytes(), true));
        }
    }

    public byte[] getChallenge() throws ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new GetChallengeApduCommand((byte) 0));
        if (res.isOk()) {
            return res.getData();
        }
        throw new ApduConnectionException("Respuesta invalida en la obtencion de desafio con el codigo: " + res.getStatusWord());
    }

    public void verifyPin(PasswordCallback pinPc) throws ApduConnectionException {
        verifyPin(pinPc, Integer.MAX_VALUE);
    }

    private void verifyPin(PasswordCallback pinPc, int retriesLeft) throws ApduConnectionException {
        PasswordCallback psc = pinPc != null ? pinPc : retriesLeft < Integer.MAX_VALUE ? DialogBuilder.getDnieBadPinPasswordCallback(retriesLeft) : DialogBuilder.getDniePinForCertificateReadingPasswordCallback();
        VerifyApduCommand verifyCommandApdu = new VerifyApduCommand((byte) 0, psc);
        try {
            if (psc.getPassword() != null) {
                if (getConnection() instanceof Cwa14890OneConnection) {
                    ApduConnection subConection = ((Cwa14890OneConnection) getConnection()).getSubConnection();
                    if (subConection instanceof SmartCardMRTDConnection) {
                        ((SmartCardMRTDConnection) subConection).idch.setSecureMessaging(null);
                    }
                }
                ResponseApdu verifyResponse = getConnection().transmit(verifyCommandApdu);
                psc.clearPassword();
                System.gc();
                if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
                    verifyPin(pinPc, verifyResponse.getStatusWord().getLsb() + 64);
                } else if (verifyResponse.getStatusWord().getMsb() == (byte) 105 && verifyResponse.getStatusWord().getLsb() == (byte) -125) {
                    throw new AuthenticationModeLockedException();
                }
            }
        } catch (ApduConnectionException e) {
            throw e;
        } catch (AuthenticationModeLockedException e2) {
            throw e2;
        } catch (Exception e3) {
            Log.e("Iso7816FourCard", "Error en la presentacion del PIN: " + e3.getMessage());
            throw new ApduConnectionException("Error en la presentacion del PIN... " + e3.getMessage());
        }
    }
}
