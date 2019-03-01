package org.bouncycastle.crypto.digests;

import custom.org.apache.harmony.security.provider.crypto.SHA1_Data;
import org.bouncycastle.util.Memoable;

public class MD4Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 16;
    private static final int S11 = 3;
    private static final int S12 = 7;
    private static final int S13 = 11;
    private static final int S14 = 19;
    private static final int S21 = 3;
    private static final int S22 = 5;
    private static final int S23 = 9;
    private static final int S24 = 13;
    private static final int S31 = 3;
    private static final int S32 = 9;
    private static final int S33 = 11;
    private static final int S34 = 15;
    private int H1;
    private int H2;
    private int H3;
    private int H4;
    /* renamed from: X */
    private int[] f622X;
    private int xOff;

    public MD4Digest() {
        this.f622X = new int[16];
        reset();
    }

    public MD4Digest(MD4Digest mD4Digest) {
        super(mD4Digest);
        this.f622X = new int[16];
        copyIn(mD4Digest);
    }

    /* renamed from: F */
    private int m29F(int i, int i2, int i3) {
        return (i & i2) | ((i ^ -1) & i3);
    }

    /* renamed from: G */
    private int m30G(int i, int i2, int i3) {
        return ((i & i2) | (i & i3)) | (i2 & i3);
    }

    /* renamed from: H */
    private int m31H(int i, int i2, int i3) {
        return (i ^ i2) ^ i3;
    }

    private void copyIn(MD4Digest mD4Digest) {
        super.copyIn(mD4Digest);
        this.H1 = mD4Digest.H1;
        this.H2 = mD4Digest.H2;
        this.H3 = mD4Digest.H3;
        this.H4 = mD4Digest.H4;
        System.arraycopy(mD4Digest.f622X, 0, this.f622X, 0, mD4Digest.f622X.length);
        this.xOff = mD4Digest.xOff;
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
        return new MD4Digest(this);
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
        return "MD4";
    }

    public int getDigestSize() {
        return 16;
    }

    protected void processBlock() {
        int i = this.H1;
        int i2 = this.H2;
        int i3 = this.H3;
        int i4 = this.H4;
        i = rotateLeft((i + m29F(i2, i3, i4)) + this.f622X[0], 3);
        i4 = rotateLeft((i4 + m29F(i, i2, i3)) + this.f622X[1], 7);
        i3 = rotateLeft((i3 + m29F(i4, i, i2)) + this.f622X[2], 11);
        i2 = rotateLeft((i2 + m29F(i3, i4, i)) + this.f622X[3], 19);
        i = rotateLeft((i + m29F(i2, i3, i4)) + this.f622X[4], 3);
        i4 = rotateLeft((i4 + m29F(i, i2, i3)) + this.f622X[5], 7);
        i3 = rotateLeft((i3 + m29F(i4, i, i2)) + this.f622X[6], 11);
        i2 = rotateLeft((i2 + m29F(i3, i4, i)) + this.f622X[7], 19);
        i = rotateLeft((i + m29F(i2, i3, i4)) + this.f622X[8], 3);
        i4 = rotateLeft((i4 + m29F(i, i2, i3)) + this.f622X[9], 7);
        i3 = rotateLeft((i3 + m29F(i4, i, i2)) + this.f622X[10], 11);
        i2 = rotateLeft((i2 + m29F(i3, i4, i)) + this.f622X[11], 19);
        i = rotateLeft((i + m29F(i2, i3, i4)) + this.f622X[12], 3);
        i4 = rotateLeft((i4 + m29F(i, i2, i3)) + this.f622X[13], 7);
        i3 = rotateLeft((i3 + m29F(i4, i, i2)) + this.f622X[14], 11);
        i2 = rotateLeft((i2 + m29F(i3, i4, i)) + this.f622X[15], 19);
        i = rotateLeft(((i + m30G(i2, i3, i4)) + this.f622X[0]) + 1518500249, 3);
        i4 = rotateLeft(((i4 + m30G(i, i2, i3)) + this.f622X[4]) + 1518500249, 5);
        i3 = rotateLeft(((i3 + m30G(i4, i, i2)) + this.f622X[8]) + 1518500249, 9);
        i2 = rotateLeft(((i2 + m30G(i3, i4, i)) + this.f622X[12]) + 1518500249, 13);
        i = rotateLeft(((i + m30G(i2, i3, i4)) + this.f622X[1]) + 1518500249, 3);
        i4 = rotateLeft(((i4 + m30G(i, i2, i3)) + this.f622X[5]) + 1518500249, 5);
        i3 = rotateLeft(((i3 + m30G(i4, i, i2)) + this.f622X[9]) + 1518500249, 9);
        i2 = rotateLeft(((i2 + m30G(i3, i4, i)) + this.f622X[13]) + 1518500249, 13);
        i = rotateLeft(((i + m30G(i2, i3, i4)) + this.f622X[2]) + 1518500249, 3);
        i4 = rotateLeft(((i4 + m30G(i, i2, i3)) + this.f622X[6]) + 1518500249, 5);
        i3 = rotateLeft(((i3 + m30G(i4, i, i2)) + this.f622X[10]) + 1518500249, 9);
        i2 = rotateLeft(((i2 + m30G(i3, i4, i)) + this.f622X[14]) + 1518500249, 13);
        i = rotateLeft(((i + m30G(i2, i3, i4)) + this.f622X[3]) + 1518500249, 3);
        i4 = rotateLeft(((i4 + m30G(i, i2, i3)) + this.f622X[7]) + 1518500249, 5);
        i3 = rotateLeft(((i3 + m30G(i4, i, i2)) + this.f622X[11]) + 1518500249, 9);
        i2 = rotateLeft(((i2 + m30G(i3, i4, i)) + this.f622X[15]) + 1518500249, 13);
        i = rotateLeft(((i + m31H(i2, i3, i4)) + this.f622X[0]) + 1859775393, 3);
        i4 = rotateLeft(((i4 + m31H(i, i2, i3)) + this.f622X[8]) + 1859775393, 9);
        i3 = rotateLeft(((i3 + m31H(i4, i, i2)) + this.f622X[4]) + 1859775393, 11);
        i2 = rotateLeft(((i2 + m31H(i3, i4, i)) + this.f622X[12]) + 1859775393, 15);
        i = rotateLeft(((i + m31H(i2, i3, i4)) + this.f622X[2]) + 1859775393, 3);
        i4 = rotateLeft(((i4 + m31H(i, i2, i3)) + this.f622X[10]) + 1859775393, 9);
        i3 = rotateLeft(((i3 + m31H(i4, i, i2)) + this.f622X[6]) + 1859775393, 11);
        i2 = rotateLeft(((i2 + m31H(i3, i4, i)) + this.f622X[14]) + 1859775393, 15);
        i = rotateLeft(((i + m31H(i2, i3, i4)) + this.f622X[1]) + 1859775393, 3);
        i4 = rotateLeft(((i4 + m31H(i, i2, i3)) + this.f622X[9]) + 1859775393, 9);
        i3 = rotateLeft(((i3 + m31H(i4, i, i2)) + this.f622X[5]) + 1859775393, 11);
        i2 = rotateLeft(((i2 + m31H(i3, i4, i)) + this.f622X[13]) + 1859775393, 15);
        i = rotateLeft(((i + m31H(i2, i3, i4)) + this.f622X[3]) + 1859775393, 3);
        i4 = rotateLeft(((i4 + m31H(i, i2, i3)) + this.f622X[11]) + 1859775393, 9);
        i3 = rotateLeft(((i3 + m31H(i4, i, i2)) + this.f622X[7]) + 1859775393, 11);
        i2 = rotateLeft(((i2 + m31H(i3, i4, i)) + this.f622X[15]) + 1859775393, 15);
        this.H1 = i + this.H1;
        this.H2 += i2;
        this.H3 += i3;
        this.H4 += i4;
        this.xOff = 0;
        for (i = 0; i != this.f622X.length; i++) {
            this.f622X[i] = 0;
        }
    }

    protected void processLength(long j) {
        if (this.xOff > 14) {
            processBlock();
        }
        this.f622X[14] = (int) (-1 & j);
        this.f622X[15] = (int) (j >>> 32);
    }

    protected void processWord(byte[] bArr, int i) {
        int[] iArr = this.f622X;
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
        for (int i = 0; i != this.f622X.length; i++) {
            this.f622X[i] = 0;
        }
    }

    public void reset(Memoable memoable) {
        copyIn((MD4Digest) memoable);
    }
}
