package es.gob.jmulticard.apdu.dnie;

import es.gob.jmulticard.apdu.CommandApdu;

public final class GetChipInfoApduCommand extends CommandApdu {
    private static final byte INSTRUCTION_PARAMETER_P1 = (byte) 0;
    private static final byte INSTRUCTION_PARAMETER_P2 = (byte) 0;
    private static final byte INS_GET_CHIP_INFO = (byte) -72;
    private static final byte MAXIMUM_LENGTH_EXPECTED_LE = (byte) 7;

    public GetChipInfoApduCommand() {
        super((byte) -112, INS_GET_CHIP_INFO, (byte) 0, (byte) 0, null, Integer.valueOf(String.valueOf(7)));
    }
}
