package jj2000.j2k.entropy.decoder;

import jj2000.j2k.util.ArrayUtil;
import org.bouncycastle.crypto.tls.CipherSuite;

public class MQDecoder {
    static final int[] nLPS = new int[]{1, 6, 9, 12, 29, 33, 6, 14, 14, 14, 17, 18, 20, 21, 14, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 46};
    static final int[] nMPS = new int[]{1, 2, 3, 4, 5, 38, 7, 8, 9, 10, 11, 12, 13, 29, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 45, 46};
    static final int[] qe = new int[]{22017, 13313, 6145, 2753, 1313, 545, 22017, 21505, 18433, 14337, 12289, 9217, 7169, 5633, 22017, 21505, 20737, 18433, 14337, 13313, 12289, 10241, 9217, 8705, 7169, 6145, 5633, 5121, 4609, 4353, 2753, 2497, 2209, 1313, 1089, 673, 545, 321, 273, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, 73, 37, 21, 9, 5, 1, 22017};
    static final int[] switchLM = new int[]{1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    /* renamed from: I */
    int[] f32I;
    /* renamed from: a */
    int f33a;
    /* renamed from: b */
    int f34b;
    /* renamed from: c */
    int f35c;
    int cT;
    ByteInputBuffer in;
    final int[] initStates;
    int[] mPS;
    boolean markerFound;

    public MQDecoder(ByteInputBuffer iStream, int nrOfContexts, int[] initStates) {
        this.in = iStream;
        this.f32I = new int[nrOfContexts];
        this.mPS = new int[nrOfContexts];
        this.initStates = initStates;
        init();
        resetCtxts();
    }

    public final boolean fastDecodeSymbols(int[] bits, int ctxt, int n) {
        int idx = this.f32I[ctxt];
        int q = qe[idx];
        if (q >= 16384 || n > ((this.f33a - (this.f35c >>> 16)) - 1) / q || n > ((this.f33a - 32768) / q) + 1) {
            int la = this.f33a;
            for (int i = 0; i < n; i++) {
                la -= q;
                if ((this.f35c >>> 16) >= la) {
                    this.f35c -= la << 16;
                    if (la < q) {
                        la = q;
                        bits[i] = this.mPS[ctxt];
                        idx = nMPS[idx];
                        q = qe[idx];
                        if (this.cT == 0) {
                            byteIn();
                        }
                        la <<= 1;
                        this.f35c <<= 1;
                        this.cT--;
                    } else {
                        la = q;
                        bits[i] = 1 - this.mPS[ctxt];
                        if (switchLM[idx] == 1) {
                            this.mPS[ctxt] = 1 - this.mPS[ctxt];
                        }
                        idx = nLPS[idx];
                        q = qe[idx];
                        do {
                            if (this.cT == 0) {
                                byteIn();
                            }
                            la <<= 1;
                            this.f35c <<= 1;
                            this.cT--;
                        } while (la < 32768);
                    }
                } else if (la >= 32768) {
                    bits[i] = this.mPS[ctxt];
                } else if (la >= q) {
                    bits[i] = this.mPS[ctxt];
                    idx = nMPS[idx];
                    q = qe[idx];
                    if (this.cT == 0) {
                        byteIn();
                    }
                    la <<= 1;
                    this.f35c <<= 1;
                    this.cT--;
                } else {
                    bits[i] = 1 - this.mPS[ctxt];
                    if (switchLM[idx] == 1) {
                        this.mPS[ctxt] = 1 - this.mPS[ctxt];
                    }
                    idx = nLPS[idx];
                    q = qe[idx];
                    do {
                        if (this.cT == 0) {
                            byteIn();
                        }
                        la <<= 1;
                        this.f35c <<= 1;
                        this.cT--;
                    } while (la < 32768);
                }
            }
            this.f33a = la;
            this.f32I[ctxt] = idx;
            return false;
        }
        this.f33a -= n * q;
        if (this.f33a >= 32768) {
            bits[0] = this.mPS[ctxt];
            return true;
        }
        this.f32I[ctxt] = nMPS[idx];
        if (this.cT == 0) {
            byteIn();
        }
        this.f33a <<= 1;
        this.f35c <<= 1;
        this.cT--;
        bits[0] = this.mPS[ctxt];
        return true;
    }

    public final void decodeSymbols(int[] bits, int[] cX, int n) {
        for (int i = 0; i < n; i++) {
            int ctxt = cX[i];
            int index = this.f32I[ctxt];
            int q = qe[index];
            this.f33a -= q;
            int la;
            if ((this.f35c >>> 16) >= this.f33a) {
                la = this.f33a;
                this.f35c -= la << 16;
                if (la < q) {
                    la = q;
                    bits[i] = this.mPS[ctxt];
                    this.f32I[ctxt] = nMPS[index];
                    if (this.cT == 0) {
                        byteIn();
                    }
                    la <<= 1;
                    this.f35c <<= 1;
                    this.cT--;
                } else {
                    la = q;
                    bits[i] = 1 - this.mPS[ctxt];
                    if (switchLM[index] == 1) {
                        this.mPS[ctxt] = 1 - this.mPS[ctxt];
                    }
                    this.f32I[ctxt] = nLPS[index];
                    do {
                        if (this.cT == 0) {
                            byteIn();
                        }
                        la <<= 1;
                        this.f35c <<= 1;
                        this.cT--;
                    } while (la < 32768);
                }
                this.f33a = la;
            } else if (this.f33a >= 32768) {
                bits[i] = this.mPS[ctxt];
            } else {
                la = this.f33a;
                if (la >= q) {
                    bits[i] = this.mPS[ctxt];
                    this.f32I[ctxt] = nMPS[index];
                    if (this.cT == 0) {
                        byteIn();
                    }
                    la <<= 1;
                    this.f35c <<= 1;
                    this.cT--;
                } else {
                    bits[i] = 1 - this.mPS[ctxt];
                    if (switchLM[index] == 1) {
                        this.mPS[ctxt] = 1 - this.mPS[ctxt];
                    }
                    this.f32I[ctxt] = nLPS[index];
                    do {
                        if (this.cT == 0) {
                            byteIn();
                        }
                        la <<= 1;
                        this.f35c <<= 1;
                        this.cT--;
                    } while (la < 32768);
                }
                this.f33a = la;
            }
        }
    }

    public final int decodeSymbol(int context) {
        int index = this.f32I[context];
        int q = qe[index];
        this.f33a -= q;
        int la;
        int decision;
        if ((this.f35c >>> 16) >= this.f33a) {
            la = this.f33a;
            this.f35c -= la << 16;
            if (la < q) {
                la = q;
                decision = this.mPS[context];
                this.f32I[context] = nMPS[index];
                if (this.cT == 0) {
                    byteIn();
                }
                la <<= 1;
                this.f35c <<= 1;
                this.cT--;
            } else {
                la = q;
                decision = 1 - this.mPS[context];
                if (switchLM[index] == 1) {
                    this.mPS[context] = 1 - this.mPS[context];
                }
                this.f32I[context] = nLPS[index];
                do {
                    if (this.cT == 0) {
                        byteIn();
                    }
                    la <<= 1;
                    this.f35c <<= 1;
                    this.cT--;
                } while (la < 32768);
            }
            this.f33a = la;
            return decision;
        } else if (this.f33a >= 32768) {
            return this.mPS[context];
        } else {
            la = this.f33a;
            if (la >= q) {
                decision = this.mPS[context];
                this.f32I[context] = nMPS[index];
                if (this.cT == 0) {
                    byteIn();
                }
                la <<= 1;
                this.f35c <<= 1;
                this.cT--;
            } else {
                decision = 1 - this.mPS[context];
                if (switchLM[index] == 1) {
                    this.mPS[context] = 1 - this.mPS[context];
                }
                this.f32I[context] = nLPS[index];
                do {
                    if (this.cT == 0) {
                        byteIn();
                    }
                    la <<= 1;
                    this.f35c <<= 1;
                    this.cT--;
                } while (la < 32768);
            }
            this.f33a = la;
            return decision;
        }
    }

    public boolean checkPredTerm() {
        if (this.f34b != 255 && !this.markerFound) {
            return true;
        }
        if (this.cT != 0 && !this.markerFound) {
            return true;
        }
        if (this.cT == 1) {
            return false;
        }
        if (this.cT == 0) {
            if (!this.markerFound) {
                this.f34b = this.in.read() & 255;
                if (this.f34b <= 143) {
                    return true;
                }
            }
            this.cT = 8;
        }
        int q = 32768 >> (this.cT - 1);
        this.f33a -= q;
        if ((this.f35c >>> 16) < this.f33a) {
            return true;
        }
        this.f35c -= this.f33a << 16;
        this.f33a = q;
        do {
            if (this.cT == 0) {
                byteIn();
            }
            this.f33a <<= 1;
            this.f35c <<= 1;
            this.cT--;
        } while (this.f33a < 32768);
        return false;
    }

    private void byteIn() {
        if (this.markerFound) {
            this.cT = 8;
        } else if (this.f34b == 255) {
            this.f34b = this.in.read() & 255;
            if (this.f34b > 143) {
                this.markerFound = true;
                this.cT = 8;
                return;
            }
            this.f35c += 65024 - (this.f34b << 9);
            this.cT = 7;
        } else {
            this.f34b = this.in.read() & 255;
            this.f35c += 65280 - (this.f34b << 8);
            this.cT = 8;
        }
    }

    public final int getNumCtxts() {
        return this.f32I.length;
    }

    public final void resetCtxt(int c) {
        this.f32I[c] = this.initStates[c];
        this.mPS[c] = 0;
    }

    public final void resetCtxts() {
        System.arraycopy(this.initStates, 0, this.f32I, 0, this.f32I.length);
        ArrayUtil.intArraySet(this.mPS, 0);
    }

    public final void nextSegment(byte[] buf, int off, int len) {
        this.in.setByteArray(buf, off, len);
        init();
    }

    public ByteInputBuffer getByteInputBuffer() {
        return this.in;
    }

    private void init() {
        this.markerFound = false;
        this.f34b = this.in.read() & 255;
        this.f35c = (this.f34b ^ 255) << 16;
        byteIn();
        this.f35c <<= 7;
        this.cT -= 7;
        this.f33a = 32768;
    }
}
