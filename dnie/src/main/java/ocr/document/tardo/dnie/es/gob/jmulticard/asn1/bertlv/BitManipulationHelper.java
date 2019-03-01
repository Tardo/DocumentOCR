package es.gob.jmulticard.asn1.bertlv;

final class BitManipulationHelper {
    private BitManipulationHelper() {
    }

    static boolean getBitValue(int value, int position) {
        if (position > 32) {
            throw new BerParsingException("No se puede obtener el valor del bit de la posicion  " + position + ", un entero en Java tiene solo 32 bits");
        } else if ((value & (1 << (position - 1))) == 0) {
            return false;
        } else {
            return true;
        }
    }

    static int setBitValue(int value, int position, boolean bitValue) {
        if (position > 32) {
            throw new BerParsingException("No se puede establecer el valor del bit de la posicion  " + position + ", un entero en Java tiene solo 32 bits");
        }
        int mask = 1 << (position - 1);
        if (bitValue) {
            return value | mask;
        }
        return (mask ^ -1) & value;
    }

    static byte[] mergeArrays(byte[] buf1, byte[] buf2) {
        byte[] resBuf = new byte[(buf1.length + buf2.length)];
        System.arraycopy(buf1, 0, resBuf, 0, buf1.length);
        System.arraycopy(buf2, 0, resBuf, buf1.length, buf2.length);
        return resBuf;
    }
}
