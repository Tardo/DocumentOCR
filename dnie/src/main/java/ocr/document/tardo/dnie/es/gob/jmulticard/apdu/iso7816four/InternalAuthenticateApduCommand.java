package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class InternalAuthenticateApduCommand extends CommandApdu {
    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) -120;
    private static final byte NO_INFORMATION_GIVEN = (byte) 0;

    public InternalAuthenticateApduCommand(byte cla, byte[] randomBytes, byte[] privateKeyRef) {
        super(cla, INS_INTERNAL_AUTHENTICATE, (byte) 0, (byte) 0, buildData(randomBytes, privateKeyRef), null);
    }

    private static byte[] buildData(byte[] randomBytes, byte[] privateKeyRef) {
        byte[] ret = new byte[(randomBytes.length + privateKeyRef.length)];
        System.arraycopy(randomBytes, 0, ret, 0, randomBytes.length);
        System.arraycopy(privateKeyRef, 0, ret, randomBytes.length + 0, privateKeyRef.length);
        return ret;
    }
}
