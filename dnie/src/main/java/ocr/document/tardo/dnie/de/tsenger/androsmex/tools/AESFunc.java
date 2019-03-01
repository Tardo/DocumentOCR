package de.tsenger.androsmex.tools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESFunc {
    static Cipher AESCBC;
    static byte[] AESCBCConstantIV = HexString.hexToBuffer("0BA0F8DDFEA61FB3D8DF9F566A050F78");
    static Cipher AESECB;
    static byte[] AES_HConstant = HexString.hexToBuffer("2DC2DF39420321D0CEF1FE2374029D95");
    static IvParameterSpec IV = new IvParameterSpec(AESCBCConstantIV);

    static {
        AESCBC = null;
        AESECB = null;
        try {
            AESCBC = Cipher.getInstance("AES/CBC/NOPADDING");
            AESECB = Cipher.getInstance("AES/ECB/NOPADDING");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] AESG(byte[] x1, byte[] x2) {
        SecretKey AESKey = new SecretKeySpec(x1, 0, 16, "AES");
        try {
            byte[] xor;
            synchronized (AESECB) {
                AESECB.init(2, AESKey);
                xor = xor(AESECB.doFinal(x2), x2);
            }
            return xor;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decryptPack(byte[] pack, byte[] contentKey) {
        SecretKey AESKey = new SecretKeySpec(contentKey, 0, 16, "AES");
        try {
            byte[] result;
            synchronized (AESCBC) {
                AESCBC.init(2, AESKey, IV);
                result = AESCBC.doFinal(pack);
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encryptAES128(byte[] input, byte[] contentKey) {
        SecretKey AESKey = new SecretKeySpec(contentKey, 0, 16, "AES");
        try {
            byte[] result;
            synchronized (AESECB) {
                AESECB.init(1, AESKey);
                result = AESECB.doFinal(input);
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] xor(byte[] in1, byte[] in2) {
        byte[] out = new byte[in1.length];
        for (int c = 0; c < in1.length; c++) {
            out[c] = (byte) (in1[c] ^ in2[c]);
        }
        return out;
    }
}
