package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class MseSetAuthenticationKeyApduCommand extends CommandApdu {
    private static final byte AT = (byte) -92;
    private static final byte INS_MANAGE_ENVIROMENT = (byte) 34;
    private static final byte SET_FOR_AUTHENTICATION = (byte) -63;
    private static final byte TAG_DF_NAME = (byte) -124;
    private static final byte TAG_FILE_ID = (byte) -125;

    public MseSetAuthenticationKeyApduCommand(byte cla, byte[] publicKeyFileId, byte[] privateKeyRef) {
        super(cla, INS_MANAGE_ENVIROMENT, SET_FOR_AUTHENTICATION, AT, buidData(publicKeyFileId, privateKeyRef), null);
    }

    private static byte[] buidData(byte[] publicKeyFileId, byte[] privateKeyRef) {
        byte[] publicKeyFileIdCompleted = new byte[12];
        System.arraycopy(publicKeyFileId, 0, publicKeyFileIdCompleted, publicKeyFileIdCompleted.length - publicKeyFileId.length, publicKeyFileId.length);
        for (int i = 0; i < publicKeyFileIdCompleted.length - publicKeyFileId.length; i++) {
            publicKeyFileIdCompleted[i] = (byte) 0;
        }
        byte[] ret = new byte[((publicKeyFileIdCompleted.length + privateKeyRef.length) + 4)];
        ret[0] = TAG_FILE_ID;
        ret[1] = (byte) publicKeyFileIdCompleted.length;
        System.arraycopy(publicKeyFileIdCompleted, 0, ret, 2, publicKeyFileIdCompleted.length);
        int idx = (publicKeyFileIdCompleted.length + 1) + 1;
        ret[idx] = TAG_DF_NAME;
        idx++;
        ret[idx] = (byte) privateKeyRef.length;
        System.arraycopy(privateKeyRef, 0, ret, idx + 1, privateKeyRef.length);
        return ret;
    }
}
