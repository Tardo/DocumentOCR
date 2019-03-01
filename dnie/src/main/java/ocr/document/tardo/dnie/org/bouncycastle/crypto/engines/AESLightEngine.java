package org.bouncycastle.crypto.engines;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import java.lang.reflect.Array;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.tls.CipherSuite;

public class AESLightEngine implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    /* renamed from: S */
    private static final byte[] f234S = new byte[]{(byte) 99, (byte) 124, (byte) 119, (byte) 123, (byte) -14, (byte) 107, (byte) 111, (byte) -59, (byte) 48, (byte) 1, (byte) 103, (byte) 43, (byte) -2, (byte) -41, (byte) -85, (byte) 118, (byte) -54, (byte) -126, (byte) -55, (byte) 125, (byte) -6, (byte) 89, (byte) 71, (byte) -16, (byte) -83, (byte) -44, (byte) -94, (byte) -81, (byte) -100, (byte) -92, (byte) 114, (byte) -64, (byte) -73, (byte) -3, (byte) -109, (byte) 38, (byte) 54, (byte) 63, (byte) -9, (byte) -52, (byte) 52, (byte) -91, (byte) -27, (byte) -15, (byte) 113, (byte) -40, (byte) 49, (byte) 21, (byte) 4, (byte) -57, (byte) 35, (byte) -61, (byte) 24, (byte) -106, (byte) 5, (byte) -102, (byte) 7, (byte) 18, Byte.MIN_VALUE, (byte) -30, (byte) -21, (byte) 39, (byte) -78, (byte) 117, (byte) 9, (byte) -125, (byte) 44, (byte) 26, (byte) 27, (byte) 110, (byte) 90, (byte) -96, (byte) 82, (byte) 59, (byte) -42, (byte) -77, (byte) 41, (byte) -29, (byte) 47, (byte) -124, (byte) 83, (byte) -47, (byte) 0, (byte) -19, (byte) 32, (byte) -4, (byte) -79, (byte) 91, (byte) 106, (byte) -53, (byte) -66, (byte) 57, (byte) 74, (byte) 76, (byte) 88, (byte) -49, (byte) -48, (byte) -17, (byte) -86, (byte) -5, (byte) 67, (byte) 77, (byte) 51, (byte) -123, (byte) 69, (byte) -7, (byte) 2, Byte.MAX_VALUE, (byte) 80, (byte) 60, (byte) -97, (byte) -88, (byte) 81, (byte) -93, (byte) 64, (byte) -113, (byte) -110, (byte) -99, (byte) 56, (byte) -11, (byte) -68, (byte) -74, (byte) -38, (byte) 33, (byte) 16, (byte) -1, (byte) -13, (byte) -46, (byte) -51, (byte) 12, (byte) 19, (byte) -20, (byte) 95, (byte) -105, (byte) 68, (byte) 23, (byte) -60, (byte) -89, (byte) 126, (byte) 61, (byte) 100, (byte) 93, (byte) 25, (byte) 115, (byte) 96, (byte) -127, (byte) 79, (byte) -36, (byte) 34, (byte) 42, (byte) -112, (byte) -120, (byte) 70, (byte) -18, (byte) -72, Handshake.FINISHED, (byte) -34, (byte) 94, (byte) 11, (byte) -37, (byte) -32, (byte) 50, (byte) 58, (byte) 10, (byte) 73, (byte) 6, (byte) 36, (byte) 92, (byte) -62, (byte) -45, (byte) -84, (byte) 98, (byte) -111, (byte) -107, (byte) -28, (byte) 121, (byte) -25, (byte) -56, (byte) 55, (byte) 109, (byte) -115, (byte) -43, (byte) 78, (byte) -87, (byte) 108, (byte) 86, (byte) -12, (byte) -22, (byte) 101, (byte) 122, (byte) -82, (byte) 8, (byte) -70, (byte) 120, (byte) 37, (byte) 46, (byte) 28, (byte) -90, (byte) -76, (byte) -58, (byte) -24, (byte) -35, (byte) 116, (byte) 31, (byte) 75, (byte) -67, (byte) -117, (byte) -118, (byte) 112, (byte) 62, (byte) -75, (byte) 102, (byte) 72, (byte) 3, (byte) -10, Handshake.SERVER_HELLO_DONE, (byte) 97, (byte) 53, (byte) 87, (byte) -71, (byte) -122, (byte) -63, (byte) 29, (byte) -98, (byte) -31, (byte) -8, (byte) -104, (byte) 17, (byte) 105, (byte) -39, (byte) -114, (byte) -108, (byte) -101, (byte) 30, (byte) -121, (byte) -23, (byte) -50, (byte) 85, (byte) 40, (byte) -33, (byte) -116, (byte) -95, (byte) -119, (byte) 13, (byte) -65, (byte) -26, (byte) 66, (byte) 104, (byte) 65, (byte) -103, (byte) 45, Handshake.CERTIFICATE_VERIFY, (byte) -80, (byte) 84, (byte) -69, (byte) 22};
    private static final byte[] Si = new byte[]{(byte) 82, (byte) 9, (byte) 106, (byte) -43, (byte) 48, (byte) 54, (byte) -91, (byte) 56, (byte) -65, (byte) 64, (byte) -93, (byte) -98, (byte) -127, (byte) -13, (byte) -41, (byte) -5, (byte) 124, (byte) -29, (byte) 57, (byte) -126, (byte) -101, (byte) 47, (byte) -1, (byte) -121, (byte) 52, (byte) -114, (byte) 67, (byte) 68, (byte) -60, (byte) -34, (byte) -23, (byte) -53, (byte) 84, (byte) 123, (byte) -108, (byte) 50, (byte) -90, (byte) -62, (byte) 35, (byte) 61, (byte) -18, (byte) 76, (byte) -107, (byte) 11, (byte) 66, (byte) -6, (byte) -61, (byte) 78, (byte) 8, (byte) 46, (byte) -95, (byte) 102, (byte) 40, (byte) -39, (byte) 36, (byte) -78, (byte) 118, (byte) 91, (byte) -94, (byte) 73, (byte) 109, (byte) -117, (byte) -47, (byte) 37, (byte) 114, (byte) -8, (byte) -10, (byte) 100, (byte) -122, (byte) 104, (byte) -104, (byte) 22, (byte) -44, (byte) -92, (byte) 92, (byte) -52, (byte) 93, (byte) 101, (byte) -74, (byte) -110, (byte) 108, (byte) 112, (byte) 72, (byte) 80, (byte) -3, (byte) -19, (byte) -71, (byte) -38, (byte) 94, (byte) 21, (byte) 70, (byte) 87, (byte) -89, (byte) -115, (byte) -99, (byte) -124, (byte) -112, (byte) -40, (byte) -85, (byte) 0, (byte) -116, (byte) -68, (byte) -45, (byte) 10, (byte) -9, (byte) -28, (byte) 88, (byte) 5, (byte) -72, (byte) -77, (byte) 69, (byte) 6, (byte) -48, (byte) 44, (byte) 30, (byte) -113, (byte) -54, (byte) 63, Handshake.CERTIFICATE_VERIFY, (byte) 2, (byte) -63, (byte) -81, (byte) -67, (byte) 3, (byte) 1, (byte) 19, (byte) -118, (byte) 107, (byte) 58, (byte) -111, (byte) 17, (byte) 65, (byte) 79, (byte) 103, (byte) -36, (byte) -22, (byte) -105, (byte) -14, (byte) -49, (byte) -50, (byte) -16, (byte) -76, (byte) -26, (byte) 115, (byte) -106, (byte) -84, (byte) 116, (byte) 34, (byte) -25, (byte) -83, (byte) 53, (byte) -123, (byte) -30, (byte) -7, (byte) 55, (byte) -24, (byte) 28, (byte) 117, (byte) -33, (byte) 110, (byte) 71, (byte) -15, (byte) 26, (byte) 113, (byte) 29, (byte) 41, (byte) -59, (byte) -119, (byte) 111, (byte) -73, (byte) 98, Handshake.SERVER_HELLO_DONE, (byte) -86, (byte) 24, (byte) -66, (byte) 27, (byte) -4, (byte) 86, (byte) 62, (byte) 75, (byte) -58, (byte) -46, (byte) 121, (byte) 32, (byte) -102, (byte) -37, (byte) -64, (byte) -2, (byte) 120, (byte) -51, (byte) 90, (byte) -12, (byte) 31, (byte) -35, (byte) -88, (byte) 51, (byte) -120, (byte) 7, (byte) -57, (byte) 49, (byte) -79, (byte) 18, (byte) 16, (byte) 89, (byte) 39, Byte.MIN_VALUE, (byte) -20, (byte) 95, (byte) 96, (byte) 81, Byte.MAX_VALUE, (byte) -87, (byte) 25, (byte) -75, (byte) 74, (byte) 13, (byte) 45, (byte) -27, (byte) 122, (byte) -97, (byte) -109, (byte) -55, (byte) -100, (byte) -17, (byte) -96, (byte) -32, (byte) 59, (byte) 77, (byte) -82, (byte) 42, (byte) -11, (byte) -80, (byte) -56, (byte) -21, (byte) -69, (byte) 60, (byte) -125, (byte) 83, (byte) -103, (byte) 97, (byte) 23, (byte) 43, (byte) 4, (byte) 126, (byte) -70, (byte) 119, (byte) -42, (byte) 38, (byte) -31, (byte) 105, Handshake.FINISHED, (byte) 99, (byte) 85, (byte) 33, (byte) 12, (byte) 125};
    private static final int m1 = -2139062144;
    private static final int m2 = 2139062143;
    private static final int m3 = 27;
    private static final int[] rcon = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA, 47, 94, 188, 99, 198, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, 53, 106, 212, 179, EACTags.SECURE_MESSAGING_TEMPLATE, 250, 239, 197, 145};
    private int C0;
    private int C1;
    private int C2;
    private int C3;
    private int ROUNDS;
    private int[][] WorkingKey = ((int[][]) null);
    private boolean forEncryption;

    private static int FFmulX(int i) {
        return ((m2 & i) << 1) ^ (((m1 & i) >>> 7) * 27);
    }

    private void decryptBlock(int[][] iArr) {
        int inv_mcol;
        int inv_mcol2;
        int inv_mcol3;
        this.C0 ^= iArr[this.ROUNDS][0];
        this.C1 ^= iArr[this.ROUNDS][1];
        this.C2 ^= iArr[this.ROUNDS][2];
        this.C3 ^= iArr[this.ROUNDS][3];
        int i = this.ROUNDS - 1;
        while (i > 1) {
            inv_mcol = inv_mcol((((Si[this.C0 & 255] & 255) ^ ((Si[(this.C3 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C2 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C1 >> 24) & 255] << 24)) ^ iArr[i][0];
            inv_mcol2 = inv_mcol((((Si[this.C1 & 255] & 255) ^ ((Si[(this.C0 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C3 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C2 >> 24) & 255] << 24)) ^ iArr[i][1];
            inv_mcol3 = inv_mcol((((Si[this.C2 & 255] & 255) ^ ((Si[(this.C1 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C0 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C3 >> 24) & 255] << 24)) ^ iArr[i][2];
            int i2 = i - 1;
            i = iArr[i][3] ^ inv_mcol((((Si[this.C3 & 255] & 255) ^ ((Si[(this.C2 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C1 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C0 >> 24) & 255] << 24));
            this.C0 = inv_mcol((((Si[inv_mcol & 255] & 255) ^ ((Si[(i >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol3 >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol2 >> 24) & 255] << 24)) ^ iArr[i2][0];
            this.C1 = inv_mcol((((Si[inv_mcol2 & 255] & 255) ^ ((Si[(inv_mcol >> 8) & 255] & 255) << 8)) ^ ((Si[(i >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol3 >> 24) & 255] << 24)) ^ iArr[i2][1];
            this.C2 = inv_mcol((((Si[inv_mcol3 & 255] & 255) ^ ((Si[(inv_mcol2 >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol >> 16) & 255] & 255) << 16)) ^ (Si[(i >> 24) & 255] << 24)) ^ iArr[i2][2];
            inv_mcol = inv_mcol((((Si[i & 255] & 255) ^ ((Si[(inv_mcol3 >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol2 >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol >> 24) & 255] << 24));
            i = i2 - 1;
            this.C3 = inv_mcol ^ iArr[i2][3];
        }
        inv_mcol = inv_mcol((((Si[this.C0 & 255] & 255) ^ ((Si[(this.C3 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C2 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C1 >> 24) & 255] << 24)) ^ iArr[i][0];
        inv_mcol2 = inv_mcol((((Si[this.C1 & 255] & 255) ^ ((Si[(this.C0 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C3 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C2 >> 24) & 255] << 24)) ^ iArr[i][1];
        inv_mcol3 = inv_mcol((((Si[this.C2 & 255] & 255) ^ ((Si[(this.C1 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C0 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C3 >> 24) & 255] << 24)) ^ iArr[i][2];
        i = iArr[i][3] ^ inv_mcol((((Si[this.C3 & 255] & 255) ^ ((Si[(this.C2 >> 8) & 255] & 255) << 8)) ^ ((Si[(this.C1 >> 16) & 255] & 255) << 16)) ^ (Si[(this.C0 >> 24) & 255] << 24));
        this.C0 = ((((Si[inv_mcol & 255] & 255) ^ ((Si[(i >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol3 >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol2 >> 24) & 255] << 24)) ^ iArr[0][0];
        this.C1 = ((((Si[inv_mcol2 & 255] & 255) ^ ((Si[(inv_mcol >> 8) & 255] & 255) << 8)) ^ ((Si[(i >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol3 >> 24) & 255] << 24)) ^ iArr[0][1];
        this.C2 = ((((Si[inv_mcol3 & 255] & 255) ^ ((Si[(inv_mcol2 >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol >> 16) & 255] & 255) << 16)) ^ (Si[(i >> 24) & 255] << 24)) ^ iArr[0][2];
        this.C3 = ((((Si[i & 255] & 255) ^ ((Si[(inv_mcol3 >> 8) & 255] & 255) << 8)) ^ ((Si[(inv_mcol2 >> 16) & 255] & 255) << 16)) ^ (Si[(inv_mcol >> 24) & 255] << 24)) ^ iArr[0][3];
    }

    private void encryptBlock(int[][] iArr) {
        int mcol;
        int mcol2;
        int mcol3;
        int i;
        this.C0 ^= iArr[0][0];
        this.C1 ^= iArr[0][1];
        this.C2 ^= iArr[0][2];
        this.C3 ^= iArr[0][3];
        int i2 = 1;
        while (i2 < this.ROUNDS - 1) {
            mcol = mcol((((f234S[this.C0 & 255] & 255) ^ ((f234S[(this.C1 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C2 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C3 >> 24) & 255] << 24)) ^ iArr[i2][0];
            mcol2 = mcol((((f234S[this.C1 & 255] & 255) ^ ((f234S[(this.C2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C3 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C0 >> 24) & 255] << 24)) ^ iArr[i2][1];
            mcol3 = mcol((((f234S[this.C2 & 255] & 255) ^ ((f234S[(this.C3 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C0 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C1 >> 24) & 255] << 24)) ^ iArr[i2][2];
            i = i2 + 1;
            i2 = iArr[i2][3] ^ mcol((((f234S[this.C3 & 255] & 255) ^ ((f234S[(this.C0 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C1 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C2 >> 24) & 255] << 24));
            this.C0 = mcol((((f234S[mcol & 255] & 255) ^ ((f234S[(mcol2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol3 >> 16) & 255] & 255) << 16)) ^ (f234S[(i2 >> 24) & 255] << 24)) ^ iArr[i][0];
            this.C1 = mcol((((f234S[mcol2 & 255] & 255) ^ ((f234S[(mcol3 >> 8) & 255] & 255) << 8)) ^ ((f234S[(i2 >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol >> 24) & 255] << 24)) ^ iArr[i][1];
            this.C2 = mcol((((f234S[mcol3 & 255] & 255) ^ ((f234S[(i2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol2 >> 24) & 255] << 24)) ^ iArr[i][2];
            mcol = mcol((((f234S[i2 & 255] & 255) ^ ((f234S[(mcol >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol2 >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol3 >> 24) & 255] << 24));
            i2 = i + 1;
            this.C3 = mcol ^ iArr[i][3];
        }
        mcol = mcol((((f234S[this.C0 & 255] & 255) ^ ((f234S[(this.C1 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C2 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C3 >> 24) & 255] << 24)) ^ iArr[i2][0];
        mcol2 = mcol((((f234S[this.C1 & 255] & 255) ^ ((f234S[(this.C2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C3 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C0 >> 24) & 255] << 24)) ^ iArr[i2][1];
        mcol3 = mcol((((f234S[this.C2 & 255] & 255) ^ ((f234S[(this.C3 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C0 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C1 >> 24) & 255] << 24)) ^ iArr[i2][2];
        i = i2 + 1;
        i2 = iArr[i2][3] ^ mcol((((f234S[this.C3 & 255] & 255) ^ ((f234S[(this.C0 >> 8) & 255] & 255) << 8)) ^ ((f234S[(this.C1 >> 16) & 255] & 255) << 16)) ^ (f234S[(this.C2 >> 24) & 255] << 24));
        this.C0 = ((((f234S[mcol & 255] & 255) ^ ((f234S[(mcol2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol3 >> 16) & 255] & 255) << 16)) ^ (f234S[(i2 >> 24) & 255] << 24)) ^ iArr[i][0];
        this.C1 = iArr[i][1] ^ ((((f234S[mcol2 & 255] & 255) ^ ((f234S[(mcol3 >> 8) & 255] & 255) << 8)) ^ ((f234S[(i2 >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol >> 24) & 255] << 24));
        this.C2 = ((((f234S[mcol3 & 255] & 255) ^ ((f234S[(i2 >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol2 >> 24) & 255] << 24)) ^ iArr[i][2];
        this.C3 = ((((f234S[i2 & 255] & 255) ^ ((f234S[(mcol >> 8) & 255] & 255) << 8)) ^ ((f234S[(mcol2 >> 16) & 255] & 255) << 16)) ^ (f234S[(mcol3 >> 24) & 255] << 24)) ^ iArr[i][3];
    }

    private int[][] generateWorkingKey(byte[] bArr, boolean z) {
        int length = bArr.length / 4;
        if ((length == 4 || length == 6 || length == 8) && length * 4 == bArr.length) {
            this.ROUNDS = length + 6;
            int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, new int[]{this.ROUNDS + 1, 4});
            int i = 0;
            int i2 = 0;
            while (i < bArr.length) {
                iArr[i2 >> 2][i2 & 3] = (((bArr[i] & 255) | ((bArr[i + 1] & 255) << 8)) | ((bArr[i + 2] & 255) << 16)) | (bArr[i + 3] << 24);
                i += 4;
                i2++;
            }
            int i3 = (this.ROUNDS + 1) << 2;
            i2 = length;
            while (i2 < i3) {
                i = iArr[(i2 - 1) >> 2][(i2 - 1) & 3];
                if (i2 % length == 0) {
                    i = subWord(shift(i, 8)) ^ rcon[(i2 / length) - 1];
                } else if (length > 6 && i2 % length == 4) {
                    i = subWord(i);
                }
                iArr[i2 >> 2][i2 & 3] = i ^ iArr[(i2 - length) >> 2][(i2 - length) & 3];
                i2++;
            }
            if (!z) {
                for (i = 1; i < this.ROUNDS; i++) {
                    for (i2 = 0; i2 < 4; i2++) {
                        iArr[i][i2] = inv_mcol(iArr[i][i2]);
                    }
                }
            }
            return iArr;
        }
        throw new IllegalArgumentException("Key length not 128/192/256 bits.");
    }

    private static int inv_mcol(int i) {
        int FFmulX = FFmulX(i);
        int FFmulX2 = FFmulX(FFmulX);
        int FFmulX3 = FFmulX(FFmulX2);
        int i2 = i ^ FFmulX3;
        return ((shift(FFmulX ^ i2, 8) ^ (FFmulX3 ^ (FFmulX ^ FFmulX2))) ^ shift(FFmulX2 ^ i2, 16)) ^ shift(i2, 24);
    }

    private static int mcol(int i) {
        int FFmulX = FFmulX(i);
        return ((FFmulX ^ shift(i ^ FFmulX, 8)) ^ shift(i, 16)) ^ shift(i, 24);
    }

    private void packBlock(byte[] bArr, int i) {
        int i2 = i + 1;
        bArr[i] = (byte) this.C0;
        int i3 = i2 + 1;
        bArr[i2] = (byte) (this.C0 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C0 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C0 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C1;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C1 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C1 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C1 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C2;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C2 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C2 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C2 >> 24);
        i2 = i3 + 1;
        bArr[i3] = (byte) this.C3;
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C3 >> 8);
        i2 = i3 + 1;
        bArr[i3] = (byte) (this.C3 >> 16);
        i3 = i2 + 1;
        bArr[i2] = (byte) (this.C3 >> 24);
    }

    private static int shift(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    private static int subWord(int i) {
        return (((f234S[i & 255] & 255) | ((f234S[(i >> 8) & 255] & 255) << 8)) | ((f234S[(i >> 16) & 255] & 255) << 16)) | (f234S[(i >> 24) & 255] << 24);
    }

    private void unpackBlock(byte[] bArr, int i) {
        int i2 = i + 1;
        this.C0 = bArr[i] & 255;
        int i3 = i2 + 1;
        this.C0 = ((bArr[i2] & 255) << 8) | this.C0;
        int i4 = i3 + 1;
        this.C0 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C0 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C1 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C1 = ((bArr[i2] & 255) << 8) | this.C1;
        i4 = i3 + 1;
        this.C1 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C1 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C2 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C2 = ((bArr[i2] & 255) << 8) | this.C2;
        i4 = i3 + 1;
        this.C2 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C2 |= bArr[i4] << 24;
        i2 = i3 + 1;
        this.C3 = bArr[i3] & 255;
        i3 = i2 + 1;
        this.C3 = ((bArr[i2] & 255) << 8) | this.C3;
        i4 = i3 + 1;
        this.C3 |= (bArr[i3] & 255) << 16;
        i3 = i4 + 1;
        this.C3 |= bArr[i4] << 24;
    }

    public String getAlgorithmName() {
        return "AES";
    }

    public int getBlockSize() {
        return 16;
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof KeyParameter) {
            this.WorkingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey(), z);
            this.forEncryption = z;
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to AES init - " + cipherParameters.getClass().getName());
    }

    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.WorkingKey == null) {
            throw new IllegalStateException("AES engine not initialised");
        } else if (i + 16 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i2 + 16 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            if (this.forEncryption) {
                unpackBlock(bArr, i);
                encryptBlock(this.WorkingKey);
                packBlock(bArr2, i2);
            } else {
                unpackBlock(bArr, i);
                decryptBlock(this.WorkingKey);
                packBlock(bArr2, i2);
            }
            return 16;
        }
    }

    public void reset() {
    }
}
