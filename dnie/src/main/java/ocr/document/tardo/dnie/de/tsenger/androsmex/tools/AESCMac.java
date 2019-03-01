package de.tsenger.androsmex.tools;

import java.io.ByteArrayOutputStream;

public class AESCMac {
    private static byte[] const_Rb = HexString.hexToBuffer("00000000000000000000000000000087");
    private static byte[] const_Zero = HexString.hexToBuffer("00000000000000000000000000000000");
    private ByteArrayOutputStream barros;
    private byte[] contentKey;

    public void doInit(byte[] contentKey) {
        this.contentKey = contentKey;
        this.barros = new ByteArrayOutputStream();
    }

    public void doUpdate(byte[] input, int offset, int len) {
        this.barros.write(input, offset, len);
    }

    public void doUpdate(byte[] input) {
        this.barros.write(input, 0, input.length);
    }

    public byte[] doFinal() {
        boolean lastBlockComplete;
        byte[] partInput;
        byte[] M_last;
        Object[] keys = generateSubKey(this.contentKey);
        byte[] K1 = (byte[]) keys[0];
        byte[] K2 = (byte[]) keys[1];
        byte[] input = this.barros.toByteArray();
        int numberOfRounds = (input.length + 15) / 16;
        if (numberOfRounds == 0) {
            numberOfRounds = 1;
            lastBlockComplete = false;
        } else if (input.length % 16 == 0) {
            lastBlockComplete = true;
        } else {
            lastBlockComplete = false;
        }
        int srcPos = (numberOfRounds - 1) * 16;
        if (lastBlockComplete) {
            partInput = new byte[16];
            System.arraycopy(input, srcPos, partInput, 0, 16);
            M_last = xor128(partInput, K1);
        } else {
            partInput = new byte[(input.length % 16)];
            System.arraycopy(input, srcPos, partInput, 0, input.length % 16);
            M_last = xor128(doPadding(partInput), K2);
        }
        byte[] X = (byte[]) const_Zero.clone();
        partInput = new byte[16];
        for (int i = 0; i < numberOfRounds - 1; i++) {
            System.arraycopy(input, i * 16, partInput, 0, 16);
            X = AESFunc.encryptAES128(xor128(partInput, X), this.contentKey);
        }
        return AESFunc.encryptAES128(xor128(X, M_last), this.contentKey);
    }

    public boolean doVerifyCMAC(byte[] verificationCMAC) {
        byte[] cmac = doFinal();
        if (verificationCMAC == null || verificationCMAC.length != cmac.length) {
            return false;
        }
        for (int i = 0; i < cmac.length; i++) {
            if (cmac[i] != verificationCMAC[i]) {
                return false;
            }
        }
        return true;
    }

    private byte[] doPadding(byte[] input) {
        byte[] padded = new byte[16];
        for (int j = 0; j < 16; j++) {
            if (j < input.length) {
                padded[j] = input[j];
            } else if (j == input.length) {
                padded[j] = Byte.MIN_VALUE;
            } else {
                padded[j] = (byte) 0;
            }
        }
        return padded;
    }

    public static Object[] generateSubKey(byte[] key) {
        byte[] K1;
        byte[] K2;
        byte[] L = AESFunc.encryptAES128(const_Zero, key);
        if ((L[0] & 128) == 0) {
            K1 = doLeftShiftOneBit(L);
        } else {
            K1 = xor128(doLeftShiftOneBit(L), const_Rb);
        }
        if ((K1[0] & 128) == 0) {
            K2 = doLeftShiftOneBit(K1);
        } else {
            K2 = xor128(doLeftShiftOneBit(K1), const_Rb);
        }
        return new Object[]{K1, K2};
    }

    private static byte[] xor128(byte[] input1, byte[] input2) {
        byte[] output = new byte[input1.length];
        for (int i = 0; i < input1.length; i++) {
            output[i] = (byte) ((input1[i] ^ input2[i]) & 255);
        }
        return output;
    }

    private static byte[] doLeftShiftOneBit(byte[] input) {
        byte[] output = new byte[input.length];
        byte overflow = (byte) 0;
        for (int i = input.length - 1; i >= 0; i--) {
            output[i] = (byte) ((input[i] << 1) & 255);
            output[i] = (byte) (output[i] | overflow);
            overflow = (input[i] & 128) != 0 ? (byte) 1 : (byte) 0;
        }
        return output;
    }
}
