package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class GetResponseApduCommand extends CommandApdu {
    private static final byte INS_GET_RESPONSE = (byte) -64;

    public GetResponseApduCommand(byte cla, byte le) {
        super(cla, INS_GET_RESPONSE, (byte) 0, (byte) 0, null, Integer.valueOf(String.valueOf(le)));
    }
}
