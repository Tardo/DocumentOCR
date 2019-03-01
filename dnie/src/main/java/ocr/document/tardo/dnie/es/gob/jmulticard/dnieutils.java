package es.gob.jmulticard;

public class dnieutils {
    public String convertStringToHex(String str) {
        if (str == null) {
            return null;
        }
        char[] chars = str.toCharArray();
        StringBuffer hex = new StringBuffer();
        for (char toHexString : chars) {
            hex.append(Integer.toHexString(toHexString));
        }
        return hex.toString();
    }

    public String convertHexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();
        if (hex == null) {
            return null;
        }
        for (int i = 0; i < hex.length() - 1; i += 2) {
            int decimal = Integer.parseInt(hex.substring(i, i + 2), 16);
            sb.append((char) decimal);
            temp.append(decimal);
        }
        System.out.println("Decimal : " + temp.toString());
        return sb.toString();
    }

    public String bytesToStringFormatted(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        int iCont = 0;
        StringBuffer sb = new StringBuffer();
        sb.append("\t");
        for (byte b : bytes) {
            if (iCont % 16 == 0) {
                sb.append(String.format("\n\t", new Object[]{Integer.valueOf(b & 255)}));
            }
            sb.append(String.format("%02x ", new Object[]{Integer.valueOf(b & 255)}));
            iCont++;
        }
        return sb.toString();
    }

    public String bytesToString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuffer sb = new StringBuffer();
        int len$ = bytes.length;
        for (int i$ = 0; i$ < len$; i$++) {
            sb.append(String.format("%02x ", new Object[]{Integer.valueOf(arr$[i$] & 255)}));
        }
        return sb.toString();
    }

    public String bytesToStringNoSp(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuffer sb = new StringBuffer();
        int len$ = bytes.length;
        for (int i$ = 0; i$ < len$; i$++) {
            sb.append(String.format("%02x", new Object[]{Integer.valueOf(arr$[i$] & 255)}));
        }
        return sb.toString();
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[(len / 2)];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    byte CalculaBitParidad(byte bits) {
        byte b = bits;
        bits = (byte) ((bits >> 1) ^ bits);
        bits = (byte) ((bits >> 2) ^ bits);
        if (((byte) (((byte) ((bits >> 4) ^ bits)) & 1)) == (byte) 0) {
            return (byte) (b ^ 1);
        }
        return b;
    }

    public long getTLV(int[] iTagLen, byte[] tlv) {
        int idxByte;
        int idxByte2 = 0 + 1;
        Long tag = Long.valueOf((long) tlv[0]);
        if ((tag.longValue() & 31) == 31) {
            idxByte = idxByte2 + 1;
            tag = Long.valueOf((tag.longValue() << 8) | ((long) tlv[idxByte2]));
        } else {
            idxByte = idxByte2;
        }
        if (tlv[idxByte] != (byte) -127 && tlv[idxByte] != (byte) -126) {
            iTagLen[0] = idxByte + 1;
            return (long) tlv[idxByte];
        } else if (tlv[idxByte] == (byte) -127) {
            iTagLen[0] = idxByte + 2;
            return (long) (tlv[idxByte + 1] & 255);
        } else if (tlv[idxByte] != (byte) -126) {
            return 0;
        } else {
            iTagLen[0] = idxByte + 3;
            return (long) ((tlv[idxByte + 2] + 256) & 65535);
        }
    }

    public long min(long num1, long num2) {
        return num1 > num2 ? num2 : num1;
    }
}
