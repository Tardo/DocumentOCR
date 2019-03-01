package de.tsenger.androsmex.mrtd;

import java.util.StringTokenizer;
import org.bouncycastle.asn1.eac.CertificateBody;

public class JSmexTools {
    public static byte[] stringToPin(String str) {
        int i;
        byte[] pin = new byte[8];
        for (i = 0; i < str.length(); i++) {
            pin[i] = (byte) str.charAt(i);
        }
        for (i = 7 - (str.length() - 1); i < 8; i++) {
            pin[i] = (byte) -1;
        }
        return pin;
    }

    public static byte[] parseHexString(String hexString) throws NumberFormatException {
        StringTokenizer st = new StringTokenizer(hexString);
        byte[] result = new byte[st.countTokens()];
        int i = 0;
        while (st.hasMoreTokens()) {
            char[] ca = st.nextToken().toCharArray();
            if (ca.length != 2) {
                throw new NumberFormatException();
            }
            result[i] = (byte) ((parseHexChar(ca[0]) * 16) + parseHexChar(ca[1]));
            i++;
        }
        return result;
    }

    public static byte parseHexChar(char c) throws NumberFormatException {
        if ((c >= '0' && c <= '9') || ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return (byte) Character.digit(c, 16);
        }
        throw new NumberFormatException();
    }

    public static int toUnsignedInt(byte value) {
        return (value < (byte) 0 ? 128 : 0) + (value & CertificateBody.profileType);
    }

    public static char toChar(byte value) {
        return (char) toUnsignedInt(value);
    }

    public static byte[] mergeByteArray(byte[] a1, byte[] a2) {
        byte[] newArray = new byte[(a1.length + a2.length)];
        System.arraycopy(a1, 0, newArray, 0, a1.length);
        System.arraycopy(a2, 0, newArray, a1.length, a2.length);
        return newArray;
    }

    public static String BCDByteArrayToString(byte[] ba, int start, int end) {
        StringBuffer sb = new StringBuffer();
        for (int i = start; i < end; i++) {
            sb.append(toUnsignedInt(ba[i]) >>> 4);
            sb.append(toUnsignedInt(ba[i]) & 15);
        }
        return sb.toString();
    }

    public static void copyByteArray(byte[] from, byte[] to, int fromstart, int length) {
        for (int i = 0; i < length; i++) {
            to[i] = from[i + fromstart];
        }
    }
}
