package org.bouncycastle.crypto.engines;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.tls.CipherSuite;

public final class TwofishEngine implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    private static final int GF256_FDBK = 361;
    private static final int GF256_FDBK_2 = 180;
    private static final int GF256_FDBK_4 = 90;
    private static final int INPUT_WHITEN = 0;
    private static final int MAX_KEY_BITS = 256;
    private static final int MAX_ROUNDS = 16;
    private static final int OUTPUT_WHITEN = 4;
    /* renamed from: P */
    private static final byte[][] f248P = new byte[][]{new byte[]{(byte) -87, (byte) 103, (byte) -77, (byte) -24, (byte) 4, (byte) -3, (byte) -93, (byte) 118, (byte) -102, (byte) -110, Byte.MIN_VALUE, (byte) 120, (byte) -28, (byte) -35, (byte) -47, (byte) 56, (byte) 13, (byte) -58, (byte) 53, (byte) -104, (byte) 24, (byte) -9, (byte) -20, (byte) 108, (byte) 67, (byte) 117, (byte) 55, (byte) 38, (byte) -6, (byte) 19, (byte) -108, (byte) 72, (byte) -14, (byte) -48, (byte) -117, (byte) 48, (byte) -124, (byte) 84, (byte) -33, (byte) 35, (byte) 25, (byte) 91, (byte) 61, (byte) 89, (byte) -13, (byte) -82, (byte) -94, (byte) -126, (byte) 99, (byte) 1, (byte) -125, (byte) 46, (byte) -39, (byte) 81, (byte) -101, (byte) 124, (byte) -90, (byte) -21, (byte) -91, (byte) -66, (byte) 22, (byte) 12, (byte) -29, (byte) 97, (byte) -64, (byte) -116, (byte) 58, (byte) -11, (byte) 115, (byte) 44, (byte) 37, (byte) 11, (byte) -69, (byte) 78, (byte) -119, (byte) 107, (byte) 83, (byte) 106, (byte) -76, (byte) -15, (byte) -31, (byte) -26, (byte) -67, (byte) 69, (byte) -30, (byte) -12, (byte) -74, (byte) 102, (byte) -52, (byte) -107, (byte) 3, (byte) 86, (byte) -44, (byte) 28, (byte) 30, (byte) -41, (byte) -5, (byte) -61, (byte) -114, (byte) -75, (byte) -23, (byte) -49, (byte) -65, (byte) -70, (byte) -22, (byte) 119, (byte) 57, (byte) -81, (byte) 51, (byte) -55, (byte) 98, (byte) 113, (byte) -127, (byte) 121, (byte) 9, (byte) -83, (byte) 36, (byte) -51, (byte) -7, (byte) -40, (byte) -27, (byte) -59, (byte) -71, (byte) 77, (byte) 68, (byte) 8, (byte) -122, (byte) -25, (byte) -95, (byte) 29, (byte) -86, (byte) -19, (byte) 6, (byte) 112, (byte) -78, (byte) -46, (byte) 65, (byte) 123, (byte) -96, (byte) 17, (byte) 49, (byte) -62, (byte) 39, (byte) -112, (byte) 32, (byte) -10, (byte) 96, (byte) -1, (byte) -106, (byte) 92, (byte) -79, (byte) -85, (byte) -98, (byte) -100, (byte) 82, (byte) 27, (byte) 95, (byte) -109, (byte) 10, (byte) -17, (byte) -111, (byte) -123, (byte) 73, (byte) -18, (byte) 45, (byte) 79, (byte) -113, (byte) 59, (byte) 71, (byte) -121, (byte) 109, (byte) 70, (byte) -42, (byte) 62, (byte) 105, (byte) 100, (byte) 42, (byte) -50, (byte) -53, (byte) 47, (byte) -4, (byte) -105, (byte) 5, (byte) 122, (byte) -84, Byte.MAX_VALUE, (byte) -43, (byte) 26, (byte) 75, Handshake.SERVER_HELLO_DONE, (byte) -89, (byte) 90, (byte) 40, Handshake.FINISHED, (byte) 63, (byte) 41, (byte) -120, (byte) 60, (byte) 76, (byte) 2, (byte) -72, (byte) -38, (byte) -80, (byte) 23, (byte) 85, (byte) 31, (byte) -118, (byte) 125, (byte) 87, (byte) -57, (byte) -115, (byte) 116, (byte) -73, (byte) -60, (byte) -97, (byte) 114, (byte) 126, (byte) 21, (byte) 34, (byte) 18, (byte) 88, (byte) 7, (byte) -103, (byte) 52, (byte) 110, (byte) 80, (byte) -34, (byte) 104, (byte) 101, (byte) -68, (byte) -37, (byte) -8, (byte) -56, (byte) -88, (byte) 43, (byte) 64, (byte) -36, (byte) -2, (byte) 50, (byte) -92, (byte) -54, (byte) 16, (byte) 33, (byte) -16, (byte) -45, (byte) 93, Handshake.CERTIFICATE_VERIFY, (byte) 0, (byte) 111, (byte) -99, (byte) 54, (byte) 66, (byte) 74, (byte) 94, (byte) -63, (byte) -32}, new byte[]{(byte) 117, (byte) -13, (byte) -58, (byte) -12, (byte) -37, (byte) 123, (byte) -5, (byte) -56, (byte) 74, (byte) -45, (byte) -26, (byte) 107, (byte) 69, (byte) 125, (byte) -24, (byte) 75, (byte) -42, (byte) 50, (byte) -40, (byte) -3, (byte) 55, (byte) 113, (byte) -15, (byte) -31, (byte) 48, Handshake.CERTIFICATE_VERIFY, (byte) -8, (byte) 27, (byte) -121, (byte) -6, (byte) 6, (byte) 63, (byte) 94, (byte) -70, (byte) -82, (byte) 91, (byte) -118, (byte) 0, (byte) -68, (byte) -99, (byte) 109, (byte) -63, (byte) -79, Handshake.SERVER_HELLO_DONE, Byte.MIN_VALUE, (byte) 93, (byte) -46, (byte) -43, (byte) -96, (byte) -124, (byte) 7, Handshake.FINISHED, (byte) -75, (byte) -112, (byte) 44, (byte) -93, (byte) -78, (byte) 115, (byte) 76, (byte) 84, (byte) -110, (byte) 116, (byte) 54, (byte) 81, (byte) 56, (byte) -80, (byte) -67, (byte) 90, (byte) -4, (byte) 96, (byte) 98, (byte) -106, (byte) 108, (byte) 66, (byte) -9, (byte) 16, (byte) 124, (byte) 40, (byte) 39, (byte) -116, (byte) 19, (byte) -107, (byte) -100, (byte) -57, (byte) 36, (byte) 70, (byte) 59, (byte) 112, (byte) -54, (byte) -29, (byte) -123, (byte) -53, (byte) 17, (byte) -48, (byte) -109, (byte) -72, (byte) -90, (byte) -125, (byte) 32, (byte) -1, (byte) -97, (byte) 119, (byte) -61, (byte) -52, (byte) 3, (byte) 111, (byte) 8, (byte) -65, (byte) 64, (byte) -25, (byte) 43, (byte) -30, (byte) 121, (byte) 12, (byte) -86, (byte) -126, (byte) 65, (byte) 58, (byte) -22, (byte) -71, (byte) -28, (byte) -102, (byte) -92, (byte) -105, (byte) 126, (byte) -38, (byte) 122, (byte) 23, (byte) 102, (byte) -108, (byte) -95, (byte) 29, (byte) 61, (byte) -16, (byte) -34, (byte) -77, (byte) 11, (byte) 114, (byte) -89, (byte) 28, (byte) -17, (byte) -47, (byte) 83, (byte) 62, (byte) -113, (byte) 51, (byte) 38, (byte) 95, (byte) -20, (byte) 118, (byte) 42, (byte) 73, (byte) -127, (byte) -120, (byte) -18, (byte) 33, (byte) -60, (byte) 26, (byte) -21, (byte) -39, (byte) -59, (byte) 57, (byte) -103, (byte) -51, (byte) -83, (byte) 49, (byte) -117, (byte) 1, (byte) 24, (byte) 35, (byte) -35, (byte) 31, (byte) 78, (byte) 45, (byte) -7, (byte) 72, (byte) 79, (byte) -14, (byte) 101, (byte) -114, (byte) 120, (byte) 92, (byte) 88, (byte) 25, (byte) -115, (byte) -27, (byte) -104, (byte) 87, (byte) 103, Byte.MAX_VALUE, (byte) 5, (byte) 100, (byte) -81, (byte) 99, (byte) -74, (byte) -2, (byte) -11, (byte) -73, (byte) 60, (byte) -91, (byte) -50, (byte) -23, (byte) 104, (byte) 68, (byte) -32, (byte) 77, (byte) 67, (byte) 105, (byte) 41, (byte) 46, (byte) -84, (byte) 21, (byte) 89, (byte) -88, (byte) 10, (byte) -98, (byte) 110, (byte) 71, (byte) -33, (byte) 52, (byte) 53, (byte) 106, (byte) -49, (byte) -36, (byte) 34, (byte) -55, (byte) -64, (byte) -101, (byte) -119, (byte) -44, (byte) -19, (byte) -85, (byte) 18, (byte) -94, (byte) 13, (byte) 82, (byte) -69, (byte) 2, (byte) 47, (byte) -87, (byte) -41, (byte) 97, (byte) 30, (byte) -76, (byte) 80, (byte) 4, (byte) -10, (byte) -62, (byte) 22, (byte) 37, (byte) -122, (byte) 86, (byte) 85, (byte) 9, (byte) -66, (byte) -111}};
    private static final int P_00 = 1;
    private static final int P_01 = 0;
    private static final int P_02 = 0;
    private static final int P_03 = 1;
    private static final int P_04 = 1;
    private static final int P_10 = 0;
    private static final int P_11 = 0;
    private static final int P_12 = 1;
    private static final int P_13 = 1;
    private static final int P_14 = 0;
    private static final int P_20 = 1;
    private static final int P_21 = 1;
    private static final int P_22 = 0;
    private static final int P_23 = 0;
    private static final int P_24 = 0;
    private static final int P_30 = 0;
    private static final int P_31 = 1;
    private static final int P_32 = 1;
    private static final int P_33 = 0;
    private static final int P_34 = 1;
    private static final int ROUNDS = 16;
    private static final int ROUND_SUBKEYS = 8;
    private static final int RS_GF_FDBK = 333;
    private static final int SK_BUMP = 16843009;
    private static final int SK_ROTL = 9;
    private static final int SK_STEP = 33686018;
    private static final int TOTAL_SUBKEYS = 40;
    private boolean encrypting = false;
    private int[] gMDS0 = new int[256];
    private int[] gMDS1 = new int[256];
    private int[] gMDS2 = new int[256];
    private int[] gMDS3 = new int[256];
    private int[] gSBox;
    private int[] gSubKeys;
    private int k64Cnt = 0;
    private byte[] workingKey = null;

    public TwofishEngine() {
        int[] iArr = new int[2];
        int[] iArr2 = new int[2];
        int[] iArr3 = new int[2];
        for (int i = 0; i < 256; i++) {
            int i2 = f248P[0][i] & 255;
            iArr[0] = i2;
            iArr2[0] = Mx_X(i2) & 255;
            iArr3[0] = Mx_Y(i2) & 255;
            i2 = f248P[1][i] & 255;
            iArr[1] = i2;
            iArr2[1] = Mx_X(i2) & 255;
            iArr3[1] = Mx_Y(i2) & 255;
            this.gMDS0[i] = ((iArr[1] | (iArr2[1] << 8)) | (iArr3[1] << 16)) | (iArr3[1] << 24);
            this.gMDS1[i] = ((iArr3[0] | (iArr3[0] << 8)) | (iArr2[0] << 16)) | (iArr[0] << 24);
            this.gMDS2[i] = ((iArr2[1] | (iArr3[1] << 8)) | (iArr[1] << 16)) | (iArr3[1] << 24);
            this.gMDS3[i] = ((iArr2[0] | (iArr[0] << 8)) | (iArr3[0] << 16)) | (iArr2[0] << 24);
        }
    }

    private void Bits32ToBytes(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >> 8);
        bArr[i2 + 2] = (byte) (i >> 16);
        bArr[i2 + 3] = (byte) (i >> 24);
    }

    private int BytesTo32Bits(byte[] bArr, int i) {
        return (((bArr[i] & 255) | ((bArr[i + 1] & 255) << 8)) | ((bArr[i + 2] & 255) << 16)) | ((bArr[i + 3] & 255) << 24);
    }

    private int F32(int i, int[] iArr) {
        int b0 = b0(i);
        int b1 = b1(i);
        int b2 = b2(i);
        int b3 = b3(i);
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        switch (this.k64Cnt & 3) {
            case 0:
                b0 = (f248P[1][b0] & 255) ^ b0(i5);
                b1 = (f248P[0][b1] & 255) ^ b1(i5);
                b2 = (f248P[0][b2] & 255) ^ b2(i5);
                b3 = (f248P[1][b3] & 255) ^ b3(i5);
                break;
            case 1:
                return this.gMDS3[(f248P[1][b3] & 255) ^ b3(i2)] ^ (this.gMDS2[(f248P[1][b2] & 255) ^ b2(i2)] ^ (this.gMDS1[(f248P[0][b1] & 255) ^ b1(i2)] ^ this.gMDS0[(f248P[0][b0] & 255) ^ b0(i2)]));
            case 2:
                break;
            case 3:
                break;
            default:
                return 0;
        }
        b0 = (f248P[1][b0] & 255) ^ b0(i4);
        b1 = (f248P[1][b1] & 255) ^ b1(i4);
        b2 = (f248P[0][b2] & 255) ^ b2(i4);
        b3 = (f248P[0][b3] & 255) ^ b3(i4);
        return this.gMDS3[(f248P[1][(f248P[1][b3] & 255) ^ b3(i3)] & 255) ^ b3(i2)] ^ (this.gMDS2[(f248P[1][(f248P[0][b2] & 255) ^ b2(i3)] & 255) ^ b2(i2)] ^ (this.gMDS1[(f248P[0][(f248P[1][b1] & 255) ^ b1(i3)] & 255) ^ b1(i2)] ^ this.gMDS0[(f248P[0][(f248P[0][b0] & 255) ^ b0(i3)] & 255) ^ b0(i2)]));
    }

    private int Fe32_0(int i) {
        return ((this.gSBox[((i & 255) * 2) + 0] ^ this.gSBox[(((i >>> 8) & 255) * 2) + 1]) ^ this.gSBox[(((i >>> 16) & 255) * 2) + 512]) ^ this.gSBox[(((i >>> 24) & 255) * 2) + 513];
    }

    private int Fe32_3(int i) {
        return ((this.gSBox[(((i >>> 24) & 255) * 2) + 0] ^ this.gSBox[((i & 255) * 2) + 1]) ^ this.gSBox[(((i >>> 8) & 255) * 2) + 512]) ^ this.gSBox[(((i >>> 16) & 255) * 2) + 513];
    }

    private int LFSR1(int i) {
        return ((i & 1) != 0 ? GF256_FDBK_2 : 0) ^ (i >> 1);
    }

    private int LFSR2(int i) {
        int i2 = 0;
        int i3 = ((i & 2) != 0 ? GF256_FDBK_2 : 0) ^ (i >> 2);
        if ((i & 1) != 0) {
            i2 = 90;
        }
        return i2 ^ i3;
    }

    private int Mx_X(int i) {
        return LFSR2(i) ^ i;
    }

    private int Mx_Y(int i) {
        return (LFSR1(i) ^ i) ^ LFSR2(i);
    }

    private int RS_MDS_Encode(int i, int i2) {
        int i3;
        int i4 = 0;
        for (i3 = 0; i3 < 4; i3++) {
            i2 = RS_rem(i2);
        }
        i3 = i2 ^ i;
        while (i4 < 4) {
            i3 = RS_rem(i3);
            i4++;
        }
        return i3;
    }

    private int RS_rem(int i) {
        int i2 = 0;
        int i3 = (i >>> 24) & 255;
        int i4 = (((i3 & 128) != 0 ? RS_GF_FDBK : 0) ^ (i3 << 1)) & 255;
        int i5 = i3 >>> 1;
        if ((i3 & 1) != 0) {
            i2 = CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256;
        }
        i2 = (i2 ^ i5) ^ i4;
        return ((i2 << 8) ^ ((i4 << 16) ^ ((i << 8) ^ (i2 << 24)))) ^ i3;
    }

    private int b0(int i) {
        return i & 255;
    }

    private int b1(int i) {
        return (i >>> 8) & 255;
    }

    private int b2(int i) {
        return (i >>> 16) & 255;
    }

    private int b3(int i) {
        return (i >>> 24) & 255;
    }

    private void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int BytesTo32Bits = BytesTo32Bits(bArr, i) ^ this.gSubKeys[4];
        int BytesTo32Bits2 = BytesTo32Bits(bArr, i + 4) ^ this.gSubKeys[5];
        int BytesTo32Bits3 = BytesTo32Bits(bArr, i + 8) ^ this.gSubKeys[6];
        int BytesTo32Bits4 = BytesTo32Bits(bArr, i + 12) ^ this.gSubKeys[7];
        int i3 = 39;
        for (int i4 = 0; i4 < 16; i4 += 2) {
            int Fe32_0 = Fe32_0(BytesTo32Bits);
            int Fe32_3 = Fe32_3(BytesTo32Bits2);
            int i5 = i3 - 1;
            i3 = (this.gSubKeys[i3] + ((Fe32_3 * 2) + Fe32_0)) ^ BytesTo32Bits4;
            BytesTo32Bits4 = (BytesTo32Bits3 << 1) | (BytesTo32Bits3 >>> 31);
            BytesTo32Bits3 = Fe32_0 + Fe32_3;
            Fe32_3 = i5 - 1;
            BytesTo32Bits3 = (BytesTo32Bits3 + this.gSubKeys[i5]) ^ BytesTo32Bits4;
            BytesTo32Bits4 = (i3 >>> 1) | (i3 << 31);
            i3 = Fe32_0(BytesTo32Bits3);
            Fe32_0 = Fe32_3(BytesTo32Bits4);
            i5 = Fe32_3 - 1;
            BytesTo32Bits2 ^= this.gSubKeys[Fe32_3] + ((Fe32_0 * 2) + i3);
            Fe32_0 += i3;
            i3 = i5 - 1;
            BytesTo32Bits = ((BytesTo32Bits >>> 31) | (BytesTo32Bits << 1)) ^ (Fe32_0 + this.gSubKeys[i5]);
            BytesTo32Bits2 = (BytesTo32Bits2 << 31) | (BytesTo32Bits2 >>> 1);
        }
        Bits32ToBytes(this.gSubKeys[0] ^ BytesTo32Bits3, bArr2, i2);
        Bits32ToBytes(this.gSubKeys[1] ^ BytesTo32Bits4, bArr2, i2 + 4);
        Bits32ToBytes(this.gSubKeys[2] ^ BytesTo32Bits, bArr2, i2 + 8);
        Bits32ToBytes(this.gSubKeys[3] ^ BytesTo32Bits2, bArr2, i2 + 12);
    }

    private void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int i3 = 0;
        int BytesTo32Bits = BytesTo32Bits(bArr, i) ^ this.gSubKeys[0];
        int BytesTo32Bits2 = BytesTo32Bits(bArr, i + 4) ^ this.gSubKeys[1];
        int BytesTo32Bits3 = BytesTo32Bits(bArr, i + 8) ^ this.gSubKeys[2];
        int BytesTo32Bits4 = this.gSubKeys[3] ^ BytesTo32Bits(bArr, i + 12);
        int i4 = 8;
        while (i3 < 16) {
            int Fe32_0 = Fe32_0(BytesTo32Bits);
            int Fe32_3 = Fe32_3(BytesTo32Bits2);
            int i5 = i4 + 1;
            i4 = (this.gSubKeys[i4] + (Fe32_0 + Fe32_3)) ^ BytesTo32Bits3;
            BytesTo32Bits3 = (i4 >>> 1) | (i4 << 31);
            Fe32_3 = i5 + 1;
            BytesTo32Bits4 = (((Fe32_3 * 2) + Fe32_0) + this.gSubKeys[i5]) ^ ((BytesTo32Bits4 << 1) | (BytesTo32Bits4 >>> 31));
            i4 = Fe32_0(BytesTo32Bits3);
            Fe32_0 = Fe32_3(BytesTo32Bits4);
            i5 = Fe32_3 + 1;
            BytesTo32Bits ^= this.gSubKeys[Fe32_3] + (i4 + Fe32_0);
            BytesTo32Bits = (BytesTo32Bits << 31) | (BytesTo32Bits >>> 1);
            Fe32_0 = (Fe32_0 * 2) + i4;
            i4 = i5 + 1;
            BytesTo32Bits2 = ((BytesTo32Bits2 >>> 31) | (BytesTo32Bits2 << 1)) ^ (Fe32_0 + this.gSubKeys[i5]);
            i3 += 2;
        }
        Bits32ToBytes(this.gSubKeys[4] ^ BytesTo32Bits3, bArr2, i2);
        Bits32ToBytes(this.gSubKeys[5] ^ BytesTo32Bits4, bArr2, i2 + 4);
        Bits32ToBytes(this.gSubKeys[6] ^ BytesTo32Bits, bArr2, i2 + 8);
        Bits32ToBytes(this.gSubKeys[7] ^ BytesTo32Bits2, bArr2, i2 + 12);
    }

    private void setKey(byte[] bArr) {
        int[] iArr = new int[4];
        int[] iArr2 = new int[4];
        int[] iArr3 = new int[4];
        this.gSubKeys = new int[40];
        if (this.k64Cnt < 1) {
            throw new IllegalArgumentException("Key size less than 64 bits");
        } else if (this.k64Cnt > 4) {
            throw new IllegalArgumentException("Key size larger than 256 bits");
        } else {
            int i;
            int i2;
            int F32;
            for (i = 0; i < this.k64Cnt; i++) {
                i2 = i * 8;
                iArr[i] = BytesTo32Bits(bArr, i2);
                iArr2[i] = BytesTo32Bits(bArr, i2 + 4);
                iArr3[(this.k64Cnt - 1) - i] = RS_MDS_Encode(iArr[i], iArr2[i]);
            }
            for (i = 0; i < 20; i++) {
                i2 = SK_STEP * i;
                F32 = F32(i2, iArr);
                i2 = F32(i2 + SK_BUMP, iArr2);
                i2 = (i2 >>> 24) | (i2 << 8);
                F32 += i2;
                this.gSubKeys[i * 2] = F32;
                i2 += F32;
                this.gSubKeys[(i * 2) + 1] = (i2 >>> 23) | (i2 << 9);
            }
            F32 = iArr3[0];
            int i3 = iArr3[1];
            int i4 = iArr3[2];
            int i5 = iArr3[3];
            this.gSBox = new int[1024];
            for (int i6 = 0; i6 < 256; i6++) {
                int b1;
                int b2;
                switch (this.k64Cnt & 3) {
                    case 0:
                        i2 = (f248P[1][i6] & 255) ^ b0(i5);
                        b1 = (f248P[0][i6] & 255) ^ b1(i5);
                        b2 = b2(i5) ^ (f248P[0][i6] & 255);
                        i = (f248P[1][i6] & 255) ^ b3(i5);
                        break;
                    case 1:
                        this.gSBox[i6 * 2] = this.gMDS0[(f248P[0][i6] & 255) ^ b0(F32)];
                        this.gSBox[(i6 * 2) + 1] = this.gMDS1[(f248P[0][i6] & 255) ^ b1(F32)];
                        this.gSBox[(i6 * 2) + 512] = this.gMDS2[(f248P[1][i6] & 255) ^ b2(F32)];
                        this.gSBox[(i6 * 2) + 513] = this.gMDS3[(f248P[1][i6] & 255) ^ b3(F32)];
                        continue;
                    case 2:
                        i = i6;
                        b2 = i6;
                        b1 = i6;
                        i2 = i6;
                        break;
                    case 3:
                        i = i6;
                        b2 = i6;
                        b1 = i6;
                        i2 = i6;
                        break;
                    default:
                        break;
                }
                i2 = (f248P[1][i2] & 255) ^ b0(i4);
                b1 = (f248P[1][b1] & 255) ^ b1(i4);
                b2 = (f248P[0][b2] & 255) ^ b2(i4);
                i = (f248P[0][i] & 255) ^ b3(i4);
                this.gSBox[i6 * 2] = this.gMDS0[(f248P[0][(f248P[0][i2] & 255) ^ b0(i3)] & 255) ^ b0(F32)];
                this.gSBox[(i6 * 2) + 1] = this.gMDS1[(f248P[0][(f248P[1][b1] & 255) ^ b1(i3)] & 255) ^ b1(F32)];
                this.gSBox[(i6 * 2) + 512] = this.gMDS2[(f248P[1][(f248P[0][b2] & 255) ^ b2(i3)] & 255) ^ b2(F32)];
                this.gSBox[(i6 * 2) + 513] = this.gMDS3[(f248P[1][(f248P[1][i] & 255) ^ b3(i3)] & 255) ^ b3(F32)];
            }
        }
    }

    public String getAlgorithmName() {
        return "Twofish";
    }

    public int getBlockSize() {
        return 16;
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof KeyParameter) {
            this.encrypting = z;
            this.workingKey = ((KeyParameter) cipherParameters).getKey();
            this.k64Cnt = this.workingKey.length / 8;
            setKey(this.workingKey);
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to Twofish init - " + cipherParameters.getClass().getName());
    }

    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.workingKey == null) {
            throw new IllegalStateException("Twofish not initialised");
        } else if (i + 16 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else if (i2 + 16 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            if (this.encrypting) {
                encryptBlock(bArr, i, bArr2, i2);
            } else {
                decryptBlock(bArr, i, bArr2, i2);
            }
            return 16;
        }
    }

    public void reset() {
        if (this.workingKey != null) {
            setKey(this.workingKey);
        }
    }
}
