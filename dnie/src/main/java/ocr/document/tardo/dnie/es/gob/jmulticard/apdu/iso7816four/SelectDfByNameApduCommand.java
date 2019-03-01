package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class SelectDfByNameApduCommand extends CommandApdu {
    private static final byte INS_SELECT_FILE = (byte) -92;
    private static final byte SELECT_DF_BY_NAME = (byte) 4;

    public SelectDfByNameApduCommand(byte cla, byte[] name) {
        super(cla, INS_SELECT_FILE, (byte) 4, (byte) 0, name, null);
    }
}
