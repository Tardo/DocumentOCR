package es.gob.jmulticard.jse.provider.digest;

import custom.org.apache.harmony.security.provider.crypto.SHA1_Data;

public class SHA1Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 20;
    private static final int Y1 = 1518500249;
    private static final int Y2 = 1859775393;
    private static final int Y3 = -1894007588;
    private static final int Y4 = -899497514;
    private int H1;
    private int H2;
    private int H3;
    private int H4;
    private int H5;
    /* renamed from: X */
    private int[] f612X;
    private int xOff;

    public SHA1Digest() {
        this.f612X = new int[80];
        reset();
    }

    public SHA1Digest(SHA1Digest t) {
        super(t);
        this.f612X = new int[80];
        this.H1 = t.H1;
        this.H2 = t.H2;
        this.H3 = t.H3;
        this.H4 = t.H4;
        this.H5 = t.H5;
        System.arraycopy(t.f612X, 0, this.f612X, 0, t.f612X.length);
        this.xOff = t.xOff;
    }

    public String getAlgorithmName() {
        return "SHA-1";
    }

    public int getDigestSize() {
        return 20;
    }

    protected void processWord(byte[] in, int inOff) {
        inOff++;
        inOff++;
        this.f612X[this.xOff] = (((in[inOff] << 24) | ((in[inOff] & 255) << 16)) | ((in[inOff] & 255) << 8)) | (in[inOff + 1] & 255);
        int i = this.xOff + 1;
        this.xOff = i;
        if (i == 16) {
            processBlock();
        }
    }

    protected void processLength(long bitLength) {
        if (this.xOff > 14) {
            processBlock();
        }
        this.f612X[14] = (int) (bitLength >>> 32);
        this.f612X[15] = (int) (-1 & bitLength);
    }

    public int doFinal(byte[] out, int outOff) {
        finish();
        Pack.intToBigEndian(this.H1, out, outOff);
        Pack.intToBigEndian(this.H2, out, outOff + 4);
        Pack.intToBigEndian(this.H3, out, outOff + 8);
        Pack.intToBigEndian(this.H4, out, outOff + 12);
        Pack.intToBigEndian(this.H5, out, outOff + 16);
        reset();
        return 20;
    }

    public void reset() {
        super.reset();
        this.H1 = SHA1_Data.H0;
        this.H2 = SHA1_Data.H1;
        this.H3 = SHA1_Data.H2;
        this.H4 = SHA1_Data.H3;
        this.H5 = SHA1_Data.H4;
        this.xOff = 0;
        for (int i = 0; i != this.f612X.length; i++) {
            this.f612X[i] = 0;
        }
    }

    /* renamed from: f */
    private int m26f(int u, int v, int w) {
        return (u & v) | ((u ^ -1) & w);
    }

    /* renamed from: h */
    private int m28h(int u, int v, int w) {
        return (u ^ v) ^ w;
    }

    /* renamed from: g */
    private int m27g(int u, int v, int w) {
        return ((u & v) | (u & w)) | (v & w);
    }

    protected void processBlock() {
        int i;
        for (i = 16; i < 80; i++) {
            int t = ((this.f612X[i - 3] ^ this.f612X[i - 8]) ^ this.f612X[i - 14]) ^ this.f612X[i - 16];
            this.f612X[i] = (t << 1) | (t >>> 31);
        }
        int A = this.H1;
        int B = this.H2;
        int C = this.H3;
        int D = this.H4;
        int E = this.H5;
        int j = 0;
        int idx = 0;
        while (j < 4) {
            int idx2 = idx + 1;
            E += ((((A << 5) | (A >>> 27)) + m26f(B, C, D)) + this.f612X[idx]) + Y1;
            B = (B << 30) | (B >>> 2);
            idx = idx2 + 1;
            D += ((((E << 5) | (E >>> 27)) + m26f(A, B, C)) + this.f612X[idx2]) + Y1;
            A = (A << 30) | (A >>> 2);
            idx2 = idx + 1;
            C += ((((D << 5) | (D >>> 27)) + m26f(E, A, B)) + this.f612X[idx]) + Y1;
            E = (E << 30) | (E >>> 2);
            idx = idx2 + 1;
            B += ((((C << 5) | (C >>> 27)) + m26f(D, E, A)) + this.f612X[idx2]) + Y1;
            D = (D << 30) | (D >>> 2);
            A += ((((B << 5) | (B >>> 27)) + m26f(C, D, E)) + this.f612X[idx]) + Y1;
            C = (C << 30) | (C >>> 2);
            j++;
            idx++;
        }
        j = 0;
        while (j < 4) {
            idx2 = idx + 1;
            E += ((((A << 5) | (A >>> 27)) + m28h(B, C, D)) + this.f612X[idx]) + Y2;
            B = (B << 30) | (B >>> 2);
            idx = idx2 + 1;
            D += ((((E << 5) | (E >>> 27)) + m28h(A, B, C)) + this.f612X[idx2]) + Y2;
            A = (A << 30) | (A >>> 2);
            idx2 = idx + 1;
            C += ((((D << 5) | (D >>> 27)) + m28h(E, A, B)) + this.f612X[idx]) + Y2;
            E = (E << 30) | (E >>> 2);
            idx = idx2 + 1;
            B += ((((C << 5) | (C >>> 27)) + m28h(D, E, A)) + this.f612X[idx2]) + Y2;
            D = (D << 30) | (D >>> 2);
            A += ((((B << 5) | (B >>> 27)) + m28h(C, D, E)) + this.f612X[idx]) + Y2;
            C = (C << 30) | (C >>> 2);
            j++;
            idx++;
        }
        j = 0;
        while (j < 4) {
            idx2 = idx + 1;
            E += ((((A << 5) | (A >>> 27)) + m27g(B, C, D)) + this.f612X[idx]) + Y3;
            B = (B << 30) | (B >>> 2);
            idx = idx2 + 1;
            D += ((((E << 5) | (E >>> 27)) + m27g(A, B, C)) + this.f612X[idx2]) + Y3;
            A = (A << 30) | (A >>> 2);
            idx2 = idx + 1;
            C += ((((D << 5) | (D >>> 27)) + m27g(E, A, B)) + this.f612X[idx]) + Y3;
            E = (E << 30) | (E >>> 2);
            idx = idx2 + 1;
            B += ((((C << 5) | (C >>> 27)) + m27g(D, E, A)) + this.f612X[idx2]) + Y3;
            D = (D << 30) | (D >>> 2);
            A += ((((B << 5) | (B >>> 27)) + m27g(C, D, E)) + this.f612X[idx]) + Y3;
            C = (C << 30) | (C >>> 2);
            j++;
            idx++;
        }
        j = 0;
        while (j <= 3) {
            idx2 = idx + 1;
            E += ((((A << 5) | (A >>> 27)) + m28h(B, C, D)) + this.f612X[idx]) + Y4;
            B = (B << 30) | (B >>> 2);
            idx = idx2 + 1;
            D += ((((E << 5) | (E >>> 27)) + m28h(A, B, C)) + this.f612X[idx2]) + Y4;
            A = (A << 30) | (A >>> 2);
            idx2 = idx + 1;
            C += ((((D << 5) | (D >>> 27)) + m28h(E, A, B)) + this.f612X[idx]) + Y4;
            E = (E << 30) | (E >>> 2);
            idx = idx2 + 1;
            B += ((((C << 5) | (C >>> 27)) + m28h(D, E, A)) + this.f612X[idx2]) + Y4;
            D = (D << 30) | (D >>> 2);
            A += ((((B << 5) | (B >>> 27)) + m28h(C, D, E)) + this.f612X[idx]) + Y4;
            C = (C << 30) | (C >>> 2);
            j++;
            idx++;
        }
        this.H1 += A;
        this.H2 += B;
        this.H3 += C;
        this.H4 += D;
        this.H5 += E;
        this.xOff = 0;
        for (i = 0; i < 16; i++) {
            this.f612X[i] = 0;
        }
    }
}
