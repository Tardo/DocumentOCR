package de.tsenger.androsmex.iso7816;

import de.tsenger.androsmex.IsoDepCardHandler;
import de.tsenger.androsmex.tools.HexString;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import org.bouncycastle.asn1.eac.CertificateBody;

public class FileAccess {
    IsoDepCardHandler ch = null;

    public FileAccess(IsoDepCardHandler cardHandler) {
        this.ch = cardHandler;
    }

    public byte[] getFile(byte sfid) throws SecureMessagingException, IOException {
        if (sfid > (byte) 31) {
            throw new IllegalArgumentException("Invalid Short File Identifier!");
        }
        ResponseAPDU resp = this.ch.transceive(CardCommands.readBinary(sfid, (byte) 8));
        if (resp.getSW1() != 144) {
            return null;
        }
        try {
            return readFile(getLength(resp.getData()));
        } catch (IOException e) {
            return null;
        }
    }

    public byte[] getFile(byte[] fid) throws SecureMessagingException, IOException {
        if (fid.length != 2) {
            throw new IllegalArgumentException("Length of FID must be 2.");
        } else if ((fid[0] & 16) == 16) {
            throw new IllegalArgumentException("Bit 8 of P1 must be 0 if READ BINARY with FID is used");
        } else {
            ResponseAPDU resp = this.ch.transceive(CardCommands.selectEF(fid));
            if (resp.getSW1() != 144) {
                throw new IOException("Couldn't select EF with FID " + HexString.bufferToHex(fid) + ", RAPDU was " + HexString.bufferToHex(resp.getBytes()));
            }
            resp = this.ch.transceive(CardCommands.readBinary((byte) 0, (byte) 0, (byte) 8));
            if (resp.getSW1() == 144) {
                return readFile(getLength(resp.getData()));
            }
            throw new IOException("Couldn't read EF with FID " + HexString.bufferToHex(fid) + ", RAPDU was " + HexString.bufferToHex(resp.getBytes()));
        }
    }

    private byte[] readFile(int length) throws SecureMessagingException, IOException {
        int remainingBytes = length;
        byte[] fileData = new byte[length];
        int i = 0;
        do {
            ResponseAPDU resp;
            int offset = i * 255;
            byte off1 = (byte) ((65280 & offset) >> 8);
            byte off2 = (byte) (offset & 255);
            if (remainingBytes <= 255) {
                resp = this.ch.transceive(CardCommands.readBinary(off1, off2, (byte) remainingBytes));
                remainingBytes = 0;
            } else {
                resp = this.ch.transceive(CardCommands.readBinary(off1, off2, (byte) 255));
                remainingBytes -= 255;
            }
            System.arraycopy(resp.getData(), 0, fileData, i * 255, resp.getData().length);
            i++;
        } while (remainingBytes > 0);
        return fileData;
    }

    private int getLength(byte[] b) throws IOException {
        ByteArrayInputStream s = new ByteArrayInputStream(b);
        int size = 0;
        s.read();
        int length = s.read();
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        } else if (length == 128) {
            return -1;
        } else {
            if (length > CertificateBody.profileType) {
                size = length & CertificateBody.profileType;
                if (size > 4) {
                    throw new IOException("DER length more than 4 bytes: " + size);
                }
                length = 0;
                for (int i = 0; i < size; i++) {
                    int next = s.read();
                    if (next < 0) {
                        throw new EOFException("EOF found reading length");
                    }
                    length = (length << 8) + next;
                }
                if (length < 0) {
                    throw new IOException("corrupted stream - negative length found");
                }
            }
            return (length + size) + 2;
        }
    }
}
