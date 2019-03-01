package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class ReadBinaryApduCommand extends CommandApdu {
    private static final byte INS_READ_BINARY = (byte) -80;

    public ReadBinaryApduCommand(byte cla, byte msbOffset, byte lsbOffset, int readLength) {
        super(cla, INS_READ_BINARY, msbOffset, lsbOffset, null, Integer.valueOf(String.valueOf(readLength)));
    }
}
