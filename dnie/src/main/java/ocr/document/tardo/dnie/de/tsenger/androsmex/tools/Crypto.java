package de.tsenger.androsmex.tools;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.params.KeyParameter;

public class Crypto {
    public static byte[] padByteArray(byte[] data) {
        byte[] tempdata = new byte[(data.length + 8)];
        int i = 0;
        while (i < data.length) {
            tempdata[i] = data[i];
            i++;
        }
        tempdata[i] = Byte.MIN_VALUE;
        i++;
        while (i % 8 != 0) {
            tempdata[i] = (byte) 0;
            i++;
        }
        byte[] filledArray = new byte[i];
        System.arraycopy(tempdata, 0, filledArray, 0, i);
        return filledArray;
    }

    public static byte[] removePadding(byte[] b) {
        int i = b.length - 1;
        do {
            i--;
        } while (b[i] == (byte) 0);
        if (b[i] != Byte.MIN_VALUE) {
            return b;
        }
        byte[] rd = new byte[i];
        System.arraycopy(b, 0, rd, 0, rd.length);
        return rd;
    }

    public static byte[] xorArray(byte[] a, byte[] b) throws IllegalArgumentException {
        if (b.length < a.length) {
            throw new IllegalArgumentException("length of byte [] b must be >= byte [] a");
        }
        byte[] c = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            c[i] = (byte) (a[i] ^ b[i]);
        }
        return c;
    }

    public static byte[] tripleDES(boolean encrypt, byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec iv = new IvParameterSpec(new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0});
        SecretKeySpec skey = new SecretKeySpec(key, "DESede");
        Cipher des = Cipher.getInstance("DESede/CBC/NoPadding");
        if (encrypt) {
            des.init(1, skey, iv);
        } else {
            des.init(2, skey, iv);
        }
        return des.doFinal(data);
    }

    public static byte[] computeMAC(byte[] key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher des;
        byte[] ka = new byte[8];
        byte[] kb = new byte[8];
        System.arraycopy(key, 0, ka, 0, 8);
        System.arraycopy(key, 8, kb, 0, 8);
        SecretKeySpec skeya = new SecretKeySpec(ka, "DES");
        SecretKeySpec skeyb = new SecretKeySpec(kb, "DES");
        byte[] current = new byte[8];
        byte[] mac = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0};
        plaintext = padByteArray(plaintext);
        for (int i = 0; i < plaintext.length; i += 8) {
            System.arraycopy(plaintext, i, current, 0, 8);
            mac = xorArray(current, mac);
            des = Cipher.getInstance("DES/ECB/NoPadding");
            des.init(1, skeya);
            mac = des.update(mac);
        }
        des = Cipher.getInstance("DES/ECB/NoPadding");
        des.init(2, skeyb);
        mac = des.update(mac);
        des.init(1, skeya);
        return des.doFinal(mac);
    }

    public static byte[] derivateAES128Key(byte[] K, byte[] c) {
        byte[] mergedData = new byte[(K.length + c.length)];
        System.arraycopy(K, 0, mergedData, 0, K.length);
        System.arraycopy(c, 0, mergedData, K.length, c.length);
        byte[] keydata = new byte[16];
        System.arraycopy(calculateSHA1(mergedData), 0, keydata, 0, 16);
        return keydata;
    }

    public static byte[] derivateAES128Key(byte[] K, byte[] c, byte[] r) {
        byte[] mergedData = new byte[((K.length + r.length) + c.length)];
        System.arraycopy(K, 0, mergedData, 0, K.length);
        System.arraycopy(r, 0, mergedData, K.length, r.length);
        System.arraycopy(c, 0, mergedData, K.length + r.length, c.length);
        byte[] keydata = new byte[16];
        System.arraycopy(calculateSHA1(mergedData), 0, keydata, 0, 16);
        return keydata;
    }

    public static byte[] decryptAESblock(byte[] key, byte[] z) {
        byte[] s = new byte[16];
        KeyParameter encKey = new KeyParameter(key);
        BlockCipher cipher = new AESFastEngine();
        cipher.init(false, encKey);
        cipher.processBlock(z, 0, s, 0);
        return s;
    }

    public static byte[] calculateSHA1(byte[] input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException e) {
        }
        md.update(input);
        return md.digest();
    }
}
