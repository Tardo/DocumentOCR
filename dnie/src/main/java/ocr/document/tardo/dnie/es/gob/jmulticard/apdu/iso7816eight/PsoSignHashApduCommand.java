package es.gob.jmulticard.apdu.iso7816eight;

import es.gob.jmulticard.apdu.CommandApdu;

public final class PsoSignHashApduCommand extends CommandApdu {
    private static final byte DATA_FIELD_SIGN_HASH = (byte) -102;
    private static final byte DATA_FIELD_SIGN_OPERATION = (byte) -98;
    private static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 42;

    public PsoSignHashApduCommand(byte cla, byte[] digestInfo) {
        super(cla, INS_PERFORM_SECURITY_OPERATION, DATA_FIELD_SIGN_OPERATION, DATA_FIELD_SIGN_HASH, digestInfo, null);
    }
}
