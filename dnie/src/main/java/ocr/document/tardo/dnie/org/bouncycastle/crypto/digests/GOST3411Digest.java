package org.bouncycastle.crypto.digests;

import java.lang.reflect.Array;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

public class GOST3411Digest implements ExtendedDigest, Memoable {
    private static final byte[] C2 = new byte[]{(byte) 0, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) -1, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) 0, (byte) -1, (byte) -1, (byte) 0, (byte) -1, (byte) 0, (byte) 0, (byte) -1, (byte) -1, (byte) 0, (byte) 0, (byte) 0, (byte) -1, (byte) -1, (byte) 0, (byte) -1};
    private static final int DIGEST_LENGTH = 32;
    /* renamed from: C */
    private byte[][] f478C;
    /* renamed from: H */
    private byte[] f479H;
    /* renamed from: K */
    private byte[] f480K;
    /* renamed from: L */
    private byte[] f481L;
    /* renamed from: M */
    private byte[] f482M;
    /* renamed from: S */
    byte[] f483S;
    private byte[] Sum;
    /* renamed from: U */
    byte[] f484U;
    /* renamed from: V */
    byte[] f485V;
    /* renamed from: W */
    byte[] f486W;
    /* renamed from: a */
    byte[] f487a;
    private long byteCount;
    private BlockCipher cipher;
    private byte[] sBox;
    short[] wS;
    short[] w_S;
    private byte[] xBuf;
    private int xBufOff;

    public GOST3411Digest() {
        this.f479H = new byte[32];
        this.f481L = new byte[32];
        this.f482M = new byte[32];
        this.Sum = new byte[32];
        this.f478C = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{4, 32});
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f480K = new byte[32];
        this.f487a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.f483S = new byte[32];
        this.f484U = new byte[32];
        this.f485V = new byte[32];
        this.f486W = new byte[32];
        this.sBox = GOST28147Engine.getSBox("D-A");
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(GOST3411Digest gOST3411Digest) {
        this.f479H = new byte[32];
        this.f481L = new byte[32];
        this.f482M = new byte[32];
        this.Sum = new byte[32];
        this.f478C = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{4, 32});
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f480K = new byte[32];
        this.f487a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.f483S = new byte[32];
        this.f484U = new byte[32];
        this.f485V = new byte[32];
        this.f486W = new byte[32];
        reset(gOST3411Digest);
    }

    public GOST3411Digest(byte[] bArr) {
        this.f479H = new byte[32];
        this.f481L = new byte[32];
        this.f482M = new byte[32];
        this.Sum = new byte[32];
        this.f478C = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{4, 32});
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.f480K = new byte[32];
        this.f487a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.f483S = new byte[32];
        this.f484U = new byte[32];
        this.f485V = new byte[32];
        this.f486W = new byte[32];
        this.sBox = Arrays.clone(bArr);
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    /* renamed from: A */
    private byte[] m20A(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            this.f487a[i] = (byte) (bArr[i] ^ bArr[i + 8]);
        }
        System.arraycopy(bArr, 8, bArr, 0, 24);
        System.arraycopy(this.f487a, 0, bArr, 24, 8);
        return bArr;
    }

    /* renamed from: E */
    private void m21E(byte[] bArr, byte[] bArr2, int i, byte[] bArr3, int i2) {
        this.cipher.init(true, new KeyParameter(bArr));
        this.cipher.processBlock(bArr3, i2, bArr2, i);
    }

    /* renamed from: P */
    private byte[] m22P(byte[] bArr) {
        for (int i = 0; i < 8; i++) {
            this.f480K[i * 4] = bArr[i];
            this.f480K[(i * 4) + 1] = bArr[i + 8];
            this.f480K[(i * 4) + 2] = bArr[i + 16];
            this.f480K[(i * 4) + 3] = bArr[i + 24];
        }
        return this.f480K;
    }

    private void cpyBytesToShort(byte[] bArr, short[] sArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            sArr[i] = (short) (((bArr[(i * 2) + 1] << 8) & 65280) | (bArr[i * 2] & 255));
        }
    }

    private void cpyShortToBytes(short[] sArr, byte[] bArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            bArr[(i * 2) + 1] = (byte) (sArr[i] >> 8);
            bArr[i * 2] = (byte) sArr[i];
        }
    }

    private void finish() {
        Pack.longToLittleEndian(this.byteCount * 8, this.f481L, 0);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processBlock(this.f481L, 0);
        processBlock(this.Sum, 0);
    }

    private void fw(byte[] bArr) {
        cpyBytesToShort(bArr, this.wS);
        this.w_S[15] = (short) (((((this.wS[0] ^ this.wS[1]) ^ this.wS[2]) ^ this.wS[3]) ^ this.wS[12]) ^ this.wS[15]);
        System.arraycopy(this.wS, 1, this.w_S, 0, 15);
        cpyShortToBytes(this.w_S, bArr);
    }

    private void sumByteArray(byte[] bArr) {
        int i = 0;
        int i2 = 0;
        while (i != this.Sum.length) {
            i2 += (this.Sum[i] & 255) + (bArr[i] & 255);
            this.Sum[i] = (byte) i2;
            i2 >>>= 8;
            i++;
        }
    }

    public Memoable copy() {
        return new GOST3411Digest(this);
    }

    public int doFinal(byte[] bArr, int i) {
        finish();
        System.arraycopy(this.f479H, 0, bArr, i, this.f479H.length);
        reset();
        return 32;
    }

    public String getAlgorithmName() {
        return "GOST3411";
    }

    public int getByteLength() {
        return 32;
    }

    public int getDigestSize() {
        return 32;
    }

    protected void processBlock(byte[] bArr, int i) {
        int i2;
        System.arraycopy(bArr, i, this.f482M, 0, 32);
        System.arraycopy(this.f479H, 0, this.f484U, 0, 32);
        System.arraycopy(this.f482M, 0, this.f485V, 0, 32);
        for (i2 = 0; i2 < 32; i2++) {
            this.f486W[i2] = (byte) (this.f484U[i2] ^ this.f485V[i2]);
        }
        m21E(m22P(this.f486W), this.f483S, 0, this.f479H, 0);
        for (int i3 = 1; i3 < 4; i3++) {
            byte[] A = m20A(this.f484U);
            for (i2 = 0; i2 < 32; i2++) {
                this.f484U[i2] = (byte) (A[i2] ^ this.f478C[i3][i2]);
            }
            this.f485V = m20A(m20A(this.f485V));
            for (i2 = 0; i2 < 32; i2++) {
                this.f486W[i2] = (byte) (this.f484U[i2] ^ this.f485V[i2]);
            }
            m21E(m22P(this.f486W), this.f483S, i3 * 8, this.f479H, i3 * 8);
        }
        for (i2 = 0; i2 < 12; i2++) {
            fw(this.f483S);
        }
        for (i2 = 0; i2 < 32; i2++) {
            this.f483S[i2] = (byte) (this.f483S[i2] ^ this.f482M[i2]);
        }
        fw(this.f483S);
        for (i2 = 0; i2 < 32; i2++) {
            this.f483S[i2] = (byte) (this.f479H[i2] ^ this.f483S[i2]);
        }
        for (i2 = 0; i2 < 61; i2++) {
            fw(this.f483S);
        }
        System.arraycopy(this.f483S, 0, this.f479H, 0, this.f479H.length);
    }

    public void reset() {
        int i;
        this.byteCount = 0;
        this.xBufOff = 0;
        for (i = 0; i < this.f479H.length; i++) {
            this.f479H[i] = (byte) 0;
        }
        for (i = 0; i < this.f481L.length; i++) {
            this.f481L[i] = (byte) 0;
        }
        for (i = 0; i < this.f482M.length; i++) {
            this.f482M[i] = (byte) 0;
        }
        for (i = 0; i < this.f478C[1].length; i++) {
            this.f478C[1][i] = (byte) 0;
        }
        for (i = 0; i < this.f478C[3].length; i++) {
            this.f478C[3][i] = (byte) 0;
        }
        for (i = 0; i < this.Sum.length; i++) {
            this.Sum[i] = (byte) 0;
        }
        for (i = 0; i < this.xBuf.length; i++) {
            this.xBuf[i] = (byte) 0;
        }
        System.arraycopy(C2, 0, this.f478C[2], 0, C2.length);
    }

    public void reset(Memoable memoable) {
        GOST3411Digest gOST3411Digest = (GOST3411Digest) memoable;
        this.sBox = gOST3411Digest.sBox;
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
        System.arraycopy(gOST3411Digest.f479H, 0, this.f479H, 0, gOST3411Digest.f479H.length);
        System.arraycopy(gOST3411Digest.f481L, 0, this.f481L, 0, gOST3411Digest.f481L.length);
        System.arraycopy(gOST3411Digest.f482M, 0, this.f482M, 0, gOST3411Digest.f482M.length);
        System.arraycopy(gOST3411Digest.Sum, 0, this.Sum, 0, gOST3411Digest.Sum.length);
        System.arraycopy(gOST3411Digest.f478C[1], 0, this.f478C[1], 0, gOST3411Digest.f478C[1].length);
        System.arraycopy(gOST3411Digest.f478C[2], 0, this.f478C[2], 0, gOST3411Digest.f478C[2].length);
        System.arraycopy(gOST3411Digest.f478C[3], 0, this.f478C[3], 0, gOST3411Digest.f478C[3].length);
        System.arraycopy(gOST3411Digest.xBuf, 0, this.xBuf, 0, gOST3411Digest.xBuf.length);
        this.xBufOff = gOST3411Digest.xBufOff;
        this.byteCount = gOST3411Digest.byteCount;
    }

    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = b;
        if (this.xBufOff == this.xBuf.length) {
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    public void update(byte[] bArr, int i, int i2) {
        while (this.xBufOff != 0 && i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
        while (i2 > this.xBuf.length) {
            System.arraycopy(bArr, i, this.xBuf, 0, this.xBuf.length);
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            i += this.xBuf.length;
            i2 -= this.xBuf.length;
            this.byteCount += (long) this.xBuf.length;
        }
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }
}
