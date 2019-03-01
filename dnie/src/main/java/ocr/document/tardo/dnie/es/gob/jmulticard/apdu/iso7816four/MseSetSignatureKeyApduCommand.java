package es.gob.jmulticard.apdu.iso7816four;

import es.gob.jmulticard.apdu.CommandApdu;

public final class MseSetSignatureKeyApduCommand extends CommandApdu {
    private static final byte INS_MANAGE_ENVIROMENT = (byte) 34;
    private static final byte SET_FOR_SIGN = (byte) 65;
    private static final byte SIGN_TEMPLATE = (byte) -74;
    private static final byte TAG_DF_NAME = (byte) -124;

    public MseSetSignatureKeyApduCommand(byte cla, byte[] privateKeyPath) {
        super(cla, INS_MANAGE_ENVIROMENT, SET_FOR_SIGN, SIGN_TEMPLATE, buidData(privateKeyPath), null);
    }

    private static byte[] buidData(byte[] privateKeyPath) {
        byte[] ret = new byte[(privateKeyPath.length + 2)];
        ret[0] = TAG_DF_NAME;
        ret[1] = (byte) privateKeyPath.length;
        System.arraycopy(privateKeyPath, 0, ret, 2, privateKeyPath.length);
        return ret;
    }
}
