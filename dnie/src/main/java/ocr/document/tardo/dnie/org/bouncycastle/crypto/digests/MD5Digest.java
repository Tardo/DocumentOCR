package org.bouncycastle.crypto.digests;

import custom.org.apache.harmony.security.provider.crypto.SHA1_Data;
import org.bouncycastle.util.Memoable;

public class MD5Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;
    private int H1;
    private int H2;
    private int H3;
    private int H4;
    /* renamed from: X */
    private int[] f623X;
    private int xOff;

    public MD5Digest() {
        this.f623X = new int[16];
        reset();
    }

    public MD5Digest(MD5Digest mD5Digest) {
        super(mD5Digest);
        this.f623X = new int[16];
        copyIn(mD5Digest);
    }

    /* renamed from: F */
    private int m32F(int i, int i2, int i3) {
        return (i & i2) | ((i ^ -1) & i3);
    }

    /* renamed from: G */
    private int m33G(int i, int i2, int i3) {
        return (i & i3) | ((i3 ^ -1) & i2);
    }

    /* renamed from: H */
    private int m34H(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    /* renamed from: K */
    private int m35K(int i, int i2, int i3) {
        return ((i3 ^ -1) | i) ^ i2;
    }

    private void copyIn(MD5Digest mD5Digest) {
        super.copyIn(mD5Digest);
        this.H1 = mD5Digest.H1;
        this.H2 = mD5Digest.H2;
        this.H3 = mD5Digest.H3;
        this.H4 = mD5Digest.H4;
        System.arraycopy(mD5Digest.f623X, 0, this.f623X, 0, mD5Digest.f623X.length);
        this.xOff = mD5Digest.xOff;
    }

    private int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (32 - i2));
    }

    private void unpackWord(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 3] = (byte) (i >>> 24);
    }

    public Memoable copy() {
        return new MD5Digest(this);
    }

    public int doFinal(byte[] bArr, int i) {
        finish();
        unpackWord(this.H1, bArr, i);
        unpackWord(this.H2, bArr, i + 4);
        unpackWord(this.H3, bArr, i + 8);
        unpackWord(this.H4, bArr, i + 12);
        reset();
        return 16;
    }

    public String getAlgorithmName() {
        return "MD5";
    }

    public int getDigestSize() {
        return 16;
    }

    protected void processBlock() {
        int i = this.H1;
        int i2 = this.H2;
        int i3 = this.H3;
        int i4 = this.H4;
        i = rotateLeft(((i + m32F(i2, i3, i4)) + this.f623X[0]) - 680876936, 7) + i2;
        i4 = rotateLeft(((i4 + m32F(i, i2, i3)) + this.f623X[1]) - 389564586, 12) + i;
        i3 = rotateLeft(((i3 + m32F(i4, i, i2)) + this.f623X[2]) + 606105819, 17) + i4;
        i2 = rotateLeft(((i2 + m32F(i3, i4, i)) + this.f623X[3]) - 1044525330, 22) + i3;
        i = rotateLeft(((i + m32F(i2, i3, i4)) + this.f623X[4]) - 176418897, 7) + i2;
        i4 = rotateLeft(((i4 + m32F(i, i2, i3)) + this.f623X[5]) + 1200080426, 12) + i;
        i3 = rotateLeft(((i3 + m32F(i4, i, i2)) + this.f623X[6]) - 1473231341, 17) + i4;
        i2 = rotateLeft(((i2 + m32F(i3, i4, i)) + this.f623X[7]) - 45705983, 22) + i3;
        i = rotateLeft(((i + m32F(i2, i3, i4)) + this.f623X[8]) + 1770035416, 7) + i2;
        i4 = rotateLeft(((i4 + m32F(i, i2, i3)) + this.f623X[9]) - 1958414417, 12) + i;
        i3 = rotateLeft(((i3 + m32F(i4, i, i2)) + this.f623X[10]) - 42063, 17) + i4;
        i2 = rotateLeft(((i2 + m32F(i3, i4, i)) + this.f623X[11]) - 1990404162, 22) + i3;
        i = rotateLeft(((i + m32F(i2, i3, i4)) + this.f623X[12]) + 1804603682, 7) + i2;
        i4 = rotateLeft(((i4 + m32F(i, i2, i3)) + this.f623X[13]) - 40341101, 12) + i;
        i3 = rotateLeft(((i3 + m32F(i4, i, i2)) + this.f623X[14]) - 1502002290, 17) + i4;
        i2 = rotateLeft(((i2 + m32F(i3, i4, i)) + this.f623X[15]) + 1236535329, 22) + i3;
        i = rotateLeft(((i + m33G(i2, i3, i4)) + this.f623X[1]) - 165796510, 5) + i2;
        i4 = rotateLeft(((i4 + m33G(i, i2, i3)) + this.f623X[6]) - 1069501632, 9) + i;
        i3 = rotateLeft(((i3 + m33G(i4, i, i2)) + this.f623X[11]) + 643717713, 14) + i4;
        i2 = rotateLeft(((i2 + m33G(i3, i4, i)) + this.f623X[0]) - 373897302, 20) + i3;
        i = rotateLeft(((i + m33G(i2, i3, i4)) + this.f623X[5]) - 701558691, 5) + i2;
        i4 = rotateLeft(((i4 + m33G(i, i2, i3)) + this.f623X[10]) + 38016083, 9) + i;
        i3 = rotateLeft(((i3 + m33G(i4, i, i2)) + this.f623X[15]) - 660478335, 14) + i4;
        i2 = rotateLeft(((i2 + m33G(i3, i4, i)) + this.f623X[4]) - 405537848, 20) + i3;
        i = rotateLeft(((i + m33G(i2, i3, i4)) + this.f623X[9]) + 568446438, 5) + i2;
        i4 = rotateLeft(((i4 + m33G(i, i2, i3)) + this.f623X[14]) - 1019803690, 9) + i;
        i3 = rotateLeft(((i3 + m33G(i4, i, i2)) + this.f623X[3]) - 187363961, 14) + i4;
        i2 = rotateLeft(((i2 + m33G(i3, i4, i)) + this.f623X[8]) + 1163531501, 20) + i3;
        i = rotateLeft(((i + m33G(i2, i3, i4)) + this.f623X[13]) - 1444681467, 5) + i2;
        i4 = rotateLeft(((i4 + m33G(i, i2, i3)) + this.f623X[2]) - 51403784, 9) + i;
        i3 = rotateLeft(((i3 + m33G(i4, i, i2)) + this.f623X[7]) + 1735328473, 14) + i4;
        i2 = rotateLeft(((i2 + m33G(i3, i4, i)) + this.f623X[12]) - 1926607734, 20) + i3;
        i = rotateLeft(((i + m34H(i2, i3, i4)) + this.f623X[5]) - 378558, 4) + i2;
        i4 = rotateLeft(((i4 + m34H(i, i2, i3)) + this.f623X[8]) - 2022574463, 11) + i;
        i3 = rotateLeft(((i3 + m34H(i4, i, i2)) + this.f623X[11]) + 1839030562, 16) + i4;
        i2 = rotateLeft(((i2 + m34H(i3, i4, i)) + this.f623X[14]) - 35309556, 23) + i3;
        i = rotateLeft(((i + m34H(i2, i3, i4)) + this.f623X[1]) - 1530992060, 4) + i2;
        i4 = rotateLeft(((i4 + m34H(i, i2, i3)) + this.f623X[4]) + 1272893353, 11) + i;
        i3 = rotateLeft(((i3 + m34H(i4, i, i2)) + this.f623X[7]) - 155497632, 16) + i4;
        i2 = rotateLeft(((i2 + m34H(i3, i4, i)) + this.f623X[10]) - 1094730640, 23) + i3;
        i = rotateLeft(((i + m34H(i2, i3, i4)) + this.f623X[13]) + 681279174, 4) + i2;
        i4 = rotateLeft(((i4 + m34H(i, i2, i3)) + this.f623X[0]) - 358537222, 11) + i;
        i3 = rotateLeft(((i3 + m34H(i4, i, i2)) + this.f623X[3]) - 722521979, 16) + i4;
        i2 = rotateLeft(((i2 + m34H(i3, i4, i)) + this.f623X[6]) + 76029189, 23) + i3;
        i = rotateLeft(((i + m34H(i2, i3, i4)) + this.f623X[9]) - 640364487, 4) + i2;
        i4 = rotateLeft(((i4 + m34H(i, i2, i3)) + this.f623X[12]) - 421815835, 11) + i;
        i3 = rotateLeft(((i3 + m34H(i4, i, i2)) + this.f623X[15]) + 530742520, 16) + i4;
        i2 = rotateLeft(((i2 + m34H(i3, i4, i)) + this.f623X[2]) - 995338651, 23) + i3;
        i = rotateLeft(((i + m35K(i2, i3, i4)) + this.f623X[0]) - 198630844, 6) + i2;
        i4 = rotateLeft(((i4 + m35K(i, i2, i3)) + this.f623X[7]) + 1126891415, 10) + i;
        i3 = rotateLeft(((i3 + m35K(i4, i, i2)) + this.f623X[14]) - 1416354905, 15) + i4;
        i2 = rotateLeft(((i2 + m35K(i3, i4, i)) + this.f623X[5]) - 57434055, 21) + i3;
        i = rotateLeft(((i + m35K(i2, i3, i4)) + this.f623X[12]) + 1700485571, 6) + i2;
        i4 = rotateLeft(((i4 + m35K(i, i2, i3)) + this.f623X[3]) - 1894986606, 10) + i;
        i3 = rotateLeft(((i3 + m35K(i4, i, i2)) + this.f623X[10]) - 1051523, 15) + i4;
        i2 = rotateLeft(((i2 + m35K(i3, i4, i)) + this.f623X[1]) - 2054922799, 21) + i3;
        i = rotateLeft(((i + m35K(i2, i3, i4)) + this.f623X[8]) + 1873313359, 6) + i2;
        i4 = rotateLeft(((i4 + m35K(i, i2, i3)) + this.f623X[15]) - 30611744, 10) + i;
        i3 = rotateLeft(((i3 + m35K(i4, i, i2)) + this.f623X[6]) - 1560198380, 15) + i4;
        i2 = rotateLeft(((i2 + m35K(i3, i4, i)) + this.f623X[13]) + 1309151649, 21) + i3;
        i = rotateLeft(((i + m35K(i2, i3, i4)) + this.f623X[4]) - 145523070, 6) + i2;
        i4 = rotateLeft(((i4 + m35K(i, i2, i3)) + this.f623X[11]) - 1120210379, 10) + i;
        i3 = rotateLeft(((i3 + m35K(i4, i, i2)) + this.f623X[2]) + 718787259, 15) + i4;
        i2 = rotateLeft(((i2 + m35K(i3, i4, i)) + this.f623X[9]) - 343485551, 21) + i3;
        this.H1 = i + this.H1;
        this.H2 += i2;
        this.H3 += i3;
        this.H4 += i4;
        this.xOff = 0;
        for (i = 0; i != this.f623X.length; i++) {
            this.f623X[i] = 0;
        }
    }

    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        this.f623X[14] = (int) (-1 & j);
        this.f623X[15] = (int) (j >>> 32);
    }

    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f623X;
        int i2 = this.xOff;
        this.xOff = i2 + 1;
        iArr[i2] = (((bArr[i] & 255) | ((bArr[i + 1] & 255) << 8)) | ((bArr[i + 2] & 255) << 16)) | ((bArr[i + 3] & 255) << 24);
        if (this.xOff == 16) {
            processBlock();
        }
    }

    public void reset() {
        super.reset();
        this.H1 = SHA1_Data.H0;
        this.H2 = SHA1_Data.H1;
        this.H3 = SHA1_Data.H2;
        this.H4 = SHA1_Data.H3;
        this.xOff = 0;
        for (int i = 0; i != this.f623X.length; i++) {
            this.f623X[i] = 0;
        }
    }

    public void reset(Memoable memoable) {
        copyIn((MD5Digest) memoable);
    }
}
