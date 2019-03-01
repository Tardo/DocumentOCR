package de.tsenger.androsmex.bac;

import de.tsenger.androsmex.crypto.AmDESCrypto;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.tools.Crypto;
import de.tsenger.androsmex.tools.HexString;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class BACFunctions {
    private static final byte[] PARITY = new byte[]{(byte) 8, (byte) 1, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 2, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 3, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 4, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 5, (byte) 0, (byte) 8, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 0, (byte) 8, (byte) 8, (byte) 0, (byte) 8, (byte) 0, (byte) 6, (byte) 8};
    private boolean bacEstablished = false;
    private byte[] kenc = null;
    private byte[] kicc = null;
    private byte[] kifd = null;
    private byte[] kmac = null;
    private byte[] ksenc = null;
    private byte[] ksmac = null;
    private byte[] rndicc = null;
    private byte[] rndifd = null;
    private final byte[] ssc = new byte[8];

    public BACFunctions(String mrz, byte[] cardChallenge) {
        this.rndicc = cardChallenge;
        String mrzInfo = calculateMrzInfo(mrz);
        this.kenc = calculateKENC(mrzInfo);
        this.kmac = calculateKMAC(mrzInfo);
        this.bacEstablished = false;
    }

    public byte[] getMutualAuthenticationCommand() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        this.rndifd = new byte[8];
        this.kifd = new byte[16];
        Random rand = new Random();
        rand.nextBytes(this.rndifd);
        rand.nextBytes(this.kifd);
        byte[] s = new byte[32];
        System.arraycopy(this.rndifd, 0, s, 0, this.rndifd.length);
        System.arraycopy(this.rndicc, 0, s, 8, this.rndicc.length);
        System.arraycopy(this.kifd, 0, s, 16, this.kifd.length);
        byte[] eifd = encryptTDES(this.kenc, s);
        byte[] mifd = Crypto.computeMAC(this.kmac, eifd);
        byte[] mu_data = new byte[(eifd.length + mifd.length)];
        System.arraycopy(eifd, 0, mu_data, 0, eifd.length);
        System.arraycopy(mifd, 0, mu_data, eifd.length, mifd.length);
        return mu_data;
    }

    public SecureMessaging establishBAC(byte[] mu_response) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] eicc = new byte[32];
        byte[] micc = new byte[8];
        System.arraycopy(mu_response, 0, eicc, 0, eicc.length);
        System.arraycopy(mu_response, 32, micc, 0, micc.length);
        if (Arrays.equals(Crypto.computeMAC(this.kmac, eicc), micc)) {
            byte[] r = decryptTDES(this.kenc, eicc);
            byte[] received_rndifd = new byte[8];
            System.arraycopy(r, 8, received_rndifd, 0, received_rndifd.length);
            System.out.println("r: " + HexString.bufferToHex(r) + "\nRND.IFD : " + HexString.bufferToHex(this.rndifd) + "\nRRND.IFD: " + HexString.bufferToHex(received_rndifd));
            if (Arrays.equals(this.rndifd, received_rndifd)) {
                this.kicc = new byte[16];
                System.arraycopy(r, 16, this.kicc, 0, this.kicc.length);
                calculateSessionKeys(this.kifd, this.kicc);
                System.arraycopy(this.rndicc, 4, this.ssc, 0, 4);
                System.arraycopy(this.rndifd, 4, this.ssc, 4, 4);
                this.bacEstablished = true;
            } else {
                this.bacEstablished = false;
            }
        } else {
            this.bacEstablished = false;
        }
        return new SecureMessaging(new AmDESCrypto(), this.kenc, this.ksmac, this.ssc);
    }

    private void calculateSessionKeys(byte[] kifd, byte[] kicc) {
        byte[] kseed = Crypto.xorArray(kicc, kifd);
        this.ksenc = computeKey(kseed, new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 1});
        this.ksmac = computeKey(kseed, new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 2});
    }

    private byte[] encryptTDES(byte[] key, byte[] plaintext) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        return Crypto.tripleDES(true, key, plaintext);
    }

    private byte[] decryptTDES(byte[] key, byte[] ciphertext) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        return Crypto.tripleDES(false, key, ciphertext);
    }

    private String calculateMrzInfo(String mrz) {
        String documentNr = mrz.substring(0, 10);
        String dateOfBirth = mrz.substring(13, 20);
        return documentNr + dateOfBirth + mrz.substring(21, 28);
    }

    private byte[] calculateKMAC(String mrzInfo) {
        return computeKey(calculateKSeed(mrzInfo.getBytes()), new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 2});
    }

    private byte[] calculateKENC(String mrzInfo) {
        return computeKey(calculateKSeed(mrzInfo.getBytes()), new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 1});
    }

    private byte[] calculateKSeed(byte[] mrzInfoBytes) {
        byte[] hash = calculateSHA1(mrzInfoBytes);
        byte[] kseed = new byte[16];
        for (int i = 0; i < 16; i++) {
            kseed[i] = hash[i];
        }
        return kseed;
    }

    private byte[] calculateSHA1(byte[] input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException e) {
        }
        md.update(input);
        return md.digest();
    }

    private byte[] computeKey(byte[] kseed, byte[] c) {
        byte[] d = new byte[20];
        System.arraycopy(kseed, 0, d, 0, kseed.length);
        System.arraycopy(c, 0, d, 16, c.length);
        byte[] hd = calculateSHA1(d);
        byte[] ka = new byte[8];
        byte[] kb = new byte[8];
        System.arraycopy(hd, 0, ka, 0, ka.length);
        System.arraycopy(hd, 8, kb, 0, kb.length);
        adjustParity(ka, 0);
        adjustParity(kb, 0);
        byte[] key = new byte[24];
        System.arraycopy(ka, 0, key, 0, 8);
        System.arraycopy(kb, 0, key, 8, 8);
        System.arraycopy(ka, 0, key, 16, 8);
        return key;
    }

    private void adjustParity(byte[] key, int offset) {
        for (int i = offset; i < 8; i++) {
            key[i] = (byte) ((PARITY[key[i] & 255] == (byte) 8 ? 1 : 0) ^ key[i]);
        }
    }
}
