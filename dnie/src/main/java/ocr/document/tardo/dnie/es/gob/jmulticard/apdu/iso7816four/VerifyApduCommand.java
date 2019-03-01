package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;
import javax.security.auth.callback.PasswordCallback;

public final class VerifyApduCommand extends CommandApdu {
    private static final byte INS_VERIFY = (byte) 32;
    private final PasswordCallback pwc;

    public VerifyApduCommand(byte cla, PasswordCallback pinPc) {
        super(cla, INS_VERIFY, (byte) 0, (byte) 0, new byte[]{(byte) 0}, null);
        if (pinPc == null) {
            throw new IllegalArgumentException("No se puede verificar el titular con un PasswordCallback nulo");
        }
        this.pwc = pinPc;
    }

    public byte[] getData() {
        int i;
        char[] p = this.pwc.getPassword();
        byte[] k = new byte[p.length];
        for (i = 0; i < k.length; i++) {
            k[i] = (byte) p[i];
        }
        for (i = 0; i < k.length; i++) {
            p[i] = '\u0000';
        }
        return k;
    }
}
