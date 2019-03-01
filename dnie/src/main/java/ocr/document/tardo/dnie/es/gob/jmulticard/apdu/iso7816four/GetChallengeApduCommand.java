package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class GetChallengeApduCommand extends CommandApdu {
    private static final byte INS_GET_CHALLENGE = (byte) -124;

    public GetChallengeApduCommand(byte cla) {
        super(cla, INS_GET_CHALLENGE, (byte) 0, (byte) 0, null, Integer.valueOf(String.valueOf(8)));
    }

    public GetChallengeApduCommand(byte cla, int numBytes) {
        super(cla, INS_GET_CHALLENGE, (byte) 0, (byte) 0, null, Integer.valueOf(String.valueOf(numBytes)));
    }
}
