package es.gob.jmulticard;

import java.math.BigInteger;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.entropy.decoder.EntropyDecoder;

public final class HexUtils {
    private static final char[] HEX_CHARS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', BitstreamReaderAgent.OPT_PREFIX, EntropyDecoder.OPT_PREFIX, 'D', 'E', 'F'};

    private HexUtils() {
    }

    public static boolean arrayEquals(byte[] v, byte[] w) {
        return arrayEquals(v, 0, v.length, w, 0, w.length);
    }

    public static boolean arrayEquals(byte[] v, int vOffset, int vLen, byte[] w, int wOffset, int wLen) {
        if (vLen != wLen || v.length < vOffset + vLen || w.length < wOffset + wLen) {
            return false;
        }
        for (int i = 0; i < vLen; i++) {
            if (v[i + vOffset] != w[i + wOffset]) {
                return false;
            }
        }
        return true;
    }

    public static short getShort(byte[] data, int offset) {
        return (short) getUnsignedInt(data, offset);
    }

    public static int getUnsignedInt(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }

    public static String hexify(byte[] abyte, boolean separator) {
        if (abyte == null) {
            return "null";
        }
        StringBuffer stringbuffer = new StringBuffer(256);
        int i = 0;
        for (int j = 0; j < abyte.length; j++) {
            if (separator && i > 0) {
                stringbuffer.append('-');
            }
            stringbuffer.append(HEX_CHARS[(abyte[j] >> 4) & 15]);
            stringbuffer.append(HEX_CHARS[abyte[j] & 15]);
            i++;
            if (i == 16) {
                if (separator) {
                    stringbuffer.append('\n');
                }
                i = 0;
            }
        }
        return stringbuffer.toString();
    }

    public static byte[] subArray(byte[] src, int srcPos, int length) {
        if (length == 0 || src.length < srcPos + length) {
            return null;
        }
        byte[] temp = new byte[length];
        System.arraycopy(src, srcPos, temp, 0, length);
        return temp;
    }

    public static byte[] xor(byte[] v, byte[] w) {
        byte[] xored = new BigInteger(1, v).xor(new BigInteger(1, w)).toByteArray();
        byte[] trimmedXor = new byte[v.length];
        if (xored.length >= trimmedXor.length) {
            System.arraycopy(xored, xored.length - trimmedXor.length, trimmedXor, 0, trimmedXor.length);
        } else {
            System.arraycopy(xored, 0, trimmedXor, trimmedXor.length - xored.length, xored.length);
        }
        return trimmedXor;
    }

    public static byte[] intToByteArray(int value) {
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[3 - i] = (byte) ((value >>> (((b.length - 1) - i) * 8)) & 255);
        }
        return b;
    }
}
