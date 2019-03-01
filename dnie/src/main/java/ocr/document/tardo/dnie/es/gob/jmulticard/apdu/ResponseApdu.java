package es.gob.jmulticard.apdu;

public class ResponseApdu extends Apdu {
    public ResponseApdu(byte[] fullBytes) {
        setBytes(fullBytes);
    }

    public byte[] getData() {
        byte[] dat = new byte[(getBytes().length - 2)];
        System.arraycopy(getBytes(), 0, dat, 0, getBytes().length - 2);
        return dat;
    }

    public StatusWord getStatusWord() {
        return new StatusWord(getBytes()[getBytes().length - 2], getBytes()[getBytes().length - 1]);
    }

    public boolean isOk() {
        if (getBytes() == null || getBytes().length < 2) {
            return false;
        }
        if ((getBytes()[getBytes().length - 1] == (byte) 0 && getBytes()[getBytes().length - 2] == (byte) -112) || ((getBytes()[getBytes().length - 1] == (byte) -125 && getBytes()[getBytes().length - 2] == (byte) 105) || ((getBytes()[getBytes().length - 1] & 240) == 192 && getBytes()[getBytes().length - 2] == (byte) 99))) {
            return true;
        }
        return false;
    }
}
