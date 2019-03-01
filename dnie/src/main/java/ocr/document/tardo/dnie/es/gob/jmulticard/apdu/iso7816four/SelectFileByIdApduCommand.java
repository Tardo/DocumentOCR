package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class SelectFileByIdApduCommand extends CommandApdu {
    private static final byte INS_SELECT_FILE = (byte) -92;
    private static final byte SEARCH_FIRST = (byte) 0;
    private static final byte SELECT_BY_ID = (byte) 0;

    public SelectFileByIdApduCommand(byte cla, byte[] fileId) {
        super(cla, INS_SELECT_FILE, (byte) 0, (byte) 0, fileId, null);
        if (fileId == null || fileId.length != 2) {
            throw new IllegalArgumentException("El identificador de fichero debe tener exactamente dos octetos");
        }
    }
}
