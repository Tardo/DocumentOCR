package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class ExternalAuthenticateApduCommand extends CommandApdu {
    private static final byte INS_EXTERNAL_AUTHENTICATE = (byte) -126;
    private static final byte NO_INFORMATION_GIVEN = (byte) 0;

    public ExternalAuthenticateApduCommand(byte cla, byte[] authenticationToken) {
        super(cla, INS_EXTERNAL_AUTHENTICATE, (byte) 0, (byte) 0, authenticationToken, null);
    }
}
