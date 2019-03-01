package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.asn1.Tlv;

public final class MseSetVerificationKeyApduCommand extends CommandApdu {
    private static final byte DST = (byte) -74;
    private static final byte INS_MANAGE_ENVIROMENT = (byte) 34;
    private static final byte SET_FOR_VERIFICATION = (byte) -127;
    private static final byte TAG_FILE_ID = (byte) -125;

    public MseSetVerificationKeyApduCommand(byte cla, byte[] keyFileId) {
        super(cla, INS_MANAGE_ENVIROMENT, SET_FOR_VERIFICATION, DST, new Tlv(TAG_FILE_ID, keyFileId).getBytes(), null);
    }
}
