package de.tsenger.androsmex.tools;

public class HexString {
    private static final char[] kHexChars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static String stringToHex(String s) {
        return bufferToHex(s.getBytes());
    }

    public static String bufferToHex(byte[] buffer) {
        return bufferToHex(buffer, 0, buffer.length);
    }

    public static String bufferToHex(byte[] buffer, int startOffset, int length) {
        StringBuffer hexString = new StringBuffer(length * 2);
        int endOffset = startOffset + length;
        for (int i = startOffset; i < endOffset; i++) {
            appendHexPair(buffer[i], hexString);
            hexString.append(" ");
            if ((i + 1) % 16 == 0) {
                hexString.append("\n");
            }
        }
        return hexString.toString();
    }

    public static String hexToString(String hexString) throws NumberFormatException {
        return new String(hexToBuffer(hexString));
    }

    public static byte[] hexToBuffer(String hexString) throws NumberFormatException {
        int length = hexString.length();
        byte[] buffer = new byte[((length + 1) / 2)];
        boolean evenByte = true;
        byte nextByte = (byte) 0;
        if (length % 2 == 1) {
            evenByte = false;
        }
        int i = 0;
        int bufferOffset = 0;
        while (i < length) {
            int nibble;
            int bufferOffset2;
            char c = hexString.charAt(i);
            if (c >= '0' && c <= '9') {
                nibble = c - 48;
            } else if (c >= 'A' && c <= 'F') {
                nibble = (c - 65) + 10;
            } else if (c < 'a' || c > 'f') {
                throw new NumberFormatException("Invalid hex digit '" + c + "'.");
            } else {
                nibble = (c - 97) + 10;
            }
            if (evenByte) {
                nextByte = (byte) (nibble << 4);
                bufferOffset2 = bufferOffset;
            } else {
                nextByte = (byte) (((byte) nibble) + nextByte);
                bufferOffset2 = bufferOffset + 1;
                buffer[bufferOffset] = nextByte;
            }
            if (evenByte) {
                evenByte = false;
            } else {
                evenByte = true;
            }
            i++;
            bufferOffset = bufferOffset2;
        }
        return buffer;
    }

    private static void appendHexPair(byte b, StringBuffer hexString) {
        char highNibble = kHexChars[(b & 240) >> 4];
        char lowNibble = kHexChars[b & 15];
        hexString.append(highNibble);
        hexString.append(lowNibble);
    }
}
