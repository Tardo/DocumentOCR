package de.tsenger.androsmex.iso7816;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class CardCommands {
    private CardCommands() {
    }

    public static CommandAPDU resetRetryCounter(byte passwdRef, byte[] newPasswd) {
        if (passwdRef == (byte) 2 || passwdRef == (byte) 3) {
            byte[] cmd = new byte[]{(byte) 0, (byte) 44, (byte) 2, passwdRef};
            ByteArrayOutputStream command = new ByteArrayOutputStream();
            try {
                command.write(cmd);
                command.write(newPasswd.length);
                command.write(newPasswd);
                return new CommandAPDU(command.toByteArray());
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        throw new IllegalArgumentException("Invalid password reference! Must be PIN (2) or CAN (3).");
    }

    public static CommandAPDU readBinary(byte sfid, byte readlength) {
        if (sfid > (byte) 31) {
            throw new IllegalArgumentException("Invalid Short File Identifier!");
        }
        byte P1 = (byte) (Byte.MIN_VALUE | sfid);
        return new CommandAPDU(new byte[]{(byte) 0, (byte) -80, P1, (byte) 0, readlength});
    }

    public static CommandAPDU readBinary(byte high_offset, byte low_offset, byte le) {
        return new CommandAPDU(new byte[]{(byte) 0, (byte) -80, high_offset, low_offset, le});
    }

    public static CommandAPDU selectEF(byte[] fid) {
        byte[] selectCmd = new byte[]{(byte) 0, (byte) -92, (byte) 2, (byte) 12};
        ByteArrayOutputStream command = new ByteArrayOutputStream();
        try {
            command.write(selectCmd);
            command.write(fid.length);
            command.write(fid);
            return new CommandAPDU(command.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static CommandAPDU selectApp(byte[] aid) {
        byte[] selectCmd = new byte[]{(byte) 0, (byte) -92, (byte) 4, (byte) 12};
        ByteArrayOutputStream command = new ByteArrayOutputStream();
        try {
            command.write(selectCmd);
            command.write(aid.length);
            command.write(aid);
            return new CommandAPDU(command.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
