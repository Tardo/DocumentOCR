package jj2000.j2k.entropy.decoder;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.StdEntropyCoderOptions;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.ArrayUtil;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public class StdEntropyDecoder extends EntropyDecoder implements StdEntropyCoderOptions {
    private static final boolean DO_TIMING = false;
    private static final int INT_SIGN_BIT = Integer.MIN_VALUE;
    private static final int[] MQ_INIT = new int[]{46, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private static final int[] MR_LUT = new int[512];
    private static final int MR_LUT_BITS = 9;
    private static final int MR_MASK = 511;
    private static final int NUM_CTXTS = 19;
    private static final int RLC_CTXT = 1;
    private static final int RLC_MASK_R1R2 = -536813568;
    private static final int[] SC_LUT = new int[512];
    private static final int SC_LUT_BITS = 9;
    private static final int SC_LUT_MASK = 15;
    private static final int SC_MASK = 511;
    private static final int SC_SHIFT_R1 = 4;
    private static final int SC_SHIFT_R2 = 20;
    private static final int SC_SPRED_SHIFT = 31;
    private static final int SEG_SYMBOL = 10;
    private static final int SIG_MASK_R1R2 = -2147450880;
    private static final int STATE_D_DL_R1 = 2;
    private static final int STATE_D_DL_R2 = 131072;
    private static final int STATE_D_DR_R1 = 1;
    private static final int STATE_D_DR_R2 = 65536;
    private static final int STATE_D_UL_R1 = 8;
    private static final int STATE_D_UL_R2 = 524288;
    private static final int STATE_D_UR_R1 = 4;
    private static final int STATE_D_UR_R2 = 262144;
    private static final int STATE_H_L_R1 = 128;
    private static final int STATE_H_L_R2 = 8388608;
    private static final int STATE_H_L_SIGN_R1 = 4096;
    private static final int STATE_H_L_SIGN_R2 = 268435456;
    private static final int STATE_H_R_R1 = 64;
    private static final int STATE_H_R_R2 = 4194304;
    private static final int STATE_H_R_SIGN_R1 = 2048;
    private static final int STATE_H_R_SIGN_R2 = 134217728;
    private static final int STATE_NZ_CTXT_R1 = 8192;
    private static final int STATE_NZ_CTXT_R2 = 536870912;
    private static final int STATE_PREV_MR_R1 = 256;
    private static final int STATE_PREV_MR_R2 = 16777216;
    private static final int STATE_SEP = 16;
    private static final int STATE_SIG_R1 = 32768;
    private static final int STATE_SIG_R2 = Integer.MIN_VALUE;
    private static final int STATE_VISITED_R1 = 16384;
    private static final int STATE_VISITED_R2 = 1073741824;
    private static final int STATE_V_D_R1 = 16;
    private static final int STATE_V_D_R2 = 1048576;
    private static final int STATE_V_D_SIGN_R1 = 512;
    private static final int STATE_V_D_SIGN_R2 = 33554432;
    private static final int STATE_V_U_R1 = 32;
    private static final int STATE_V_U_R2 = 2097152;
    private static final int STATE_V_U_SIGN_R1 = 1024;
    private static final int STATE_V_U_SIGN_R2 = 67108864;
    private static final int UNIF_CTXT = 0;
    private static final int VSTD_MASK_R1R2 = 1073758208;
    private static final int ZC_LUT_BITS = 8;
    private static final int[] ZC_LUT_HH = new int[256];
    private static final int[] ZC_LUT_HL = new int[256];
    private static final int[] ZC_LUT_LH = new int[256];
    private static final int ZC_MASK = 255;
    private ByteToBitInput bin;
    private DecoderSpecs decSpec;
    private final boolean doer;
    private int mQuit;
    private MQDecoder mq;
    private int options;
    private DecLyrdCBlk srcblk;
    private final int[] state;
    private long[] time;
    private final boolean verber;

    static {
        int i;
        int j;
        int[] iArr = new int[19];
        ZC_LUT_LH[0] = 2;
        for (i = 1; i < 16; i++) {
            ZC_LUT_LH[i] = 4;
        }
        for (i = 0; i < 4; i++) {
            ZC_LUT_LH[1 << i] = 3;
        }
        for (i = 0; i < 16; i++) {
            ZC_LUT_LH[i | 32] = 5;
            ZC_LUT_LH[i | 16] = 5;
            ZC_LUT_LH[i | 48] = 6;
        }
        ZC_LUT_LH[128] = 7;
        ZC_LUT_LH[64] = 7;
        for (i = 1; i < 16; i++) {
            ZC_LUT_LH[i | 128] = 8;
            ZC_LUT_LH[i | 64] = 8;
        }
        for (i = 1; i < 4; i++) {
            for (j = 0; j < 16; j++) {
                ZC_LUT_LH[((i << 4) | 128) | j] = 9;
                ZC_LUT_LH[((i << 4) | 64) | j] = 9;
            }
        }
        for (i = 0; i < 64; i++) {
            ZC_LUT_LH[i | 192] = 10;
        }
        ZC_LUT_HL[0] = 2;
        for (i = 1; i < 16; i++) {
            ZC_LUT_HL[i] = 4;
        }
        for (i = 0; i < 4; i++) {
            ZC_LUT_HL[1 << i] = 3;
        }
        for (i = 0; i < 16; i++) {
            ZC_LUT_HL[i | 128] = 5;
            ZC_LUT_HL[i | 64] = 5;
            ZC_LUT_HL[i | 192] = 6;
        }
        ZC_LUT_HL[32] = 7;
        ZC_LUT_HL[16] = 7;
        for (i = 1; i < 16; i++) {
            ZC_LUT_HL[i | 32] = 8;
            ZC_LUT_HL[i | 16] = 8;
        }
        for (i = 1; i < 4; i++) {
            for (j = 0; j < 16; j++) {
                ZC_LUT_HL[((i << 6) | 32) | j] = 9;
                ZC_LUT_HL[((i << 6) | 16) | j] = 9;
            }
        }
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 16; j++) {
                ZC_LUT_HL[(((i << 6) | 32) | 16) | j] = 10;
            }
        }
        int i2 = 6;
        int[] twoBits = new int[]{3, 5, 6, 9, 10, 12};
        i2 = 4;
        int[] oneBit = new int[]{1, 2, 4, 8};
        i2 = 11;
        int[] twoLeast = new int[]{3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
        i2 = 5;
        int[] threeLeast = new int[]{7, 11, 13, 14, 15};
        ZC_LUT_HH[0] = 2;
        for (int i3 : oneBit) {
            ZC_LUT_HH[i3 << 4] = 3;
        }
        for (int i32 : twoLeast) {
            ZC_LUT_HH[i32 << 4] = 4;
        }
        for (int i322 : oneBit) {
            ZC_LUT_HH[i322] = 5;
        }
        for (int i3222 : oneBit) {
            for (int i4 : oneBit) {
                ZC_LUT_HH[(i3222 << 4) | i4] = 6;
            }
        }
        for (int i32222 : twoLeast) {
            for (int i42 : oneBit) {
                ZC_LUT_HH[(i32222 << 4) | i42] = 7;
            }
        }
        for (int i322222 : twoBits) {
            ZC_LUT_HH[i322222] = 8;
        }
        for (int i422 : twoBits) {
            for (i = 1; i < 16; i++) {
                ZC_LUT_HH[(i << 4) | i422] = 9;
            }
        }
        for (i = 0; i < 16; i++) {
            for (int i4222 : threeLeast) {
                ZC_LUT_HH[(i << 4) | i4222] = 10;
            }
        }
        int[] inter_sc_lut = new int[36];
        inter_sc_lut[18] = 15;
        inter_sc_lut[17] = 14;
        inter_sc_lut[16] = 13;
        inter_sc_lut[10] = 12;
        inter_sc_lut[9] = 11;
        inter_sc_lut[8] = -2147483636;
        inter_sc_lut[2] = -2147483635;
        inter_sc_lut[1] = -2147483634;
        inter_sc_lut[0] = -2147483633;
        for (i = 0; i < 511; i++) {
            int ds = i & 1;
            int us = (i >> 1) & 1;
            int dsgn = (i >> 5) & 1;
            int usgn = (i >> 6) & 1;
            int h = ((1 - (((i >> 8) & 1) * 2)) * ((i >> 3) & 1)) + ((1 - (((i >> 7) & 1) * 2)) * ((i >> 2) & 1));
            if (h < -1) {
                h = -1;
            }
            if (h > 1) {
                h = 1;
            }
            int v = ((1 - (usgn * 2)) * us) + ((1 - (dsgn * 2)) * ds);
            if (v < -1) {
                v = -1;
            }
            if (v > 1) {
                v = 1;
            }
            SC_LUT[i] = inter_sc_lut[((h + 1) << 3) | (v + 1)];
        }
        MR_LUT[0] = 16;
        i = 1;
        while (i < 256) {
            MR_LUT[i] = 17;
            i++;
        }
        while (i < 512) {
            MR_LUT[i] = 18;
            i++;
        }
    }

    public StdEntropyDecoder(CodedCBlkDataSrcDec src, DecoderSpecs decSpec, boolean doer, boolean verber, int mQuit) {
        super(src);
        this.decSpec = decSpec;
        this.doer = doer;
        this.verber = verber;
        this.mQuit = mQuit;
        this.state = new int[((decSpec.cblks.getMaxCBlkWidth() + 2) * (((decSpec.cblks.getMaxCBlkHeight() + 1) / 2) + 2))];
    }

    public void finalize() throws Throwable {
        super.finalize();
    }

    public DataBlk getCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        ByteInputBuffer in = null;
        this.srcblk = this.src.getCodeBlock(c, m, n, sb, 1, -1, this.srcblk);
        this.options = ((Integer) this.decSpec.ecopts.getTileCompVal(this.tIdx, c)).intValue();
        ArrayUtil.intArraySet(this.state, 0);
        if (cblk == null) {
            cblk = new DataBlkInt();
        }
        cblk.progressive = this.srcblk.prog;
        cblk.ulx = this.srcblk.ulx;
        cblk.uly = this.srcblk.uly;
        cblk.f39w = this.srcblk.f216w;
        cblk.f38h = this.srcblk.f215h;
        cblk.offset = 0;
        cblk.scanw = cblk.f39w;
        int[] out_data = (int[]) cblk.getData();
        if (out_data == null || out_data.length < this.srcblk.f216w * this.srcblk.f215h) {
            cblk.setData(new int[(this.srcblk.f216w * this.srcblk.f215h)]);
        } else {
            ArrayUtil.intArraySet(out_data, 0);
        }
        if (this.srcblk.nl > 0 && this.srcblk.nTrunc > 0) {
            int[] zc_lut;
            boolean isterm;
            int tslen = this.srcblk.tsLengths == null ? this.srcblk.dl : this.srcblk.tsLengths[0];
            int tsidx = 0;
            int npasses = this.srcblk.nTrunc;
            if (this.mq == null) {
                ByteInputBuffer byteInputBuffer = new ByteInputBuffer(this.srcblk.data, 0, tslen);
                this.mq = new MQDecoder(byteInputBuffer, 19, MQ_INIT);
            } else {
                this.mq.nextSegment(this.srcblk.data, 0, tslen);
                this.mq.resetCtxts();
            }
            boolean error = false;
            if ((this.options & 1) != 0 && this.bin == null) {
                if (in == null) {
                    in = this.mq.getByteInputBuffer();
                }
                this.bin = new ByteToBitInput(in);
            }
            switch (sb.orientation) {
                case 0:
                case 2:
                    zc_lut = ZC_LUT_LH;
                    break;
                case 1:
                    zc_lut = ZC_LUT_HL;
                    break;
                case 3:
                    zc_lut = ZC_LUT_HH;
                    break;
                default:
                    throw new Error("JJ2000 internal error");
            }
            int curbp = 30 - this.srcblk.skipMSBP;
            if (this.mQuit != -1 && (this.mQuit * 3) - 2 < npasses) {
                npasses = (this.mQuit * 3) - 2;
            }
            if (curbp >= 0 && npasses > 0) {
                isterm = (this.options & 4) != 0 || ((this.options & 1) != 0 && 27 - this.srcblk.skipMSBP >= curbp);
                error = cleanuppass(cblk, this.mq, curbp, this.state, zc_lut, isterm);
                npasses--;
                if (!(error && this.doer)) {
                    curbp--;
                }
            }
            if (!(error && this.doer)) {
                while (curbp >= 0 && npasses > 0) {
                    if ((this.options & 1) == 0 || curbp >= 27 - this.srcblk.skipMSBP) {
                        if ((this.options & 4) != 0) {
                            tsidx++;
                            this.mq.nextSegment(null, -1, this.srcblk.tsLengths[tsidx]);
                        }
                        error = sigProgPass(cblk, this.mq, curbp, this.state, zc_lut, (this.options & 4) != 0);
                        npasses--;
                        if (npasses > 0 && !(error && this.doer)) {
                            if ((this.options & 4) != 0) {
                                tsidx++;
                                this.mq.nextSegment(null, -1, this.srcblk.tsLengths[tsidx]);
                            }
                            isterm = (this.options & 4) != 0 || ((this.options & 1) != 0 && 27 - this.srcblk.skipMSBP > curbp);
                            error = magRefPass(cblk, this.mq, curbp, this.state, isterm);
                        }
                    } else {
                        tsidx++;
                        this.bin.setByteArray(null, -1, this.srcblk.tsLengths[tsidx]);
                        error = rawSigProgPass(cblk, this.bin, curbp, this.state, (this.options & 4) != 0);
                        npasses--;
                        if (npasses > 0 && !(error && this.doer)) {
                            if ((this.options & 4) != 0) {
                                tsidx++;
                                this.bin.setByteArray(null, -1, this.srcblk.tsLengths[tsidx]);
                            }
                            isterm = (this.options & 4) != 0 || ((this.options & 1) != 0 && 27 - this.srcblk.skipMSBP > curbp);
                            error = rawMagRefPass(cblk, this.bin, curbp, this.state, isterm);
                        }
                    }
                    npasses--;
                    if (npasses > 0 && !(error && this.doer)) {
                        if ((this.options & 4) != 0 || ((this.options & 1) != 0 && curbp < 27 - this.srcblk.skipMSBP)) {
                            tsidx++;
                            this.mq.nextSegment(null, -1, this.srcblk.tsLengths[tsidx]);
                        }
                        isterm = (this.options & 4) != 0 || ((this.options & 1) != 0 && 27 - this.srcblk.skipMSBP >= curbp);
                        error = cleanuppass(cblk, this.mq, curbp, this.state, zc_lut, isterm);
                        npasses--;
                        if (!error || !this.doer) {
                            curbp--;
                        }
                    }
                }
            }
            if (error && this.doer) {
                if (this.verber) {
                    FacilityManager.getMsgLogger().printmsg(2, "Error detected at bit-plane " + curbp + " in code-block (" + m + "," + n + "), sb_idx " + sb.sbandIdx + ", res. level " + sb.resLvl + ". Concealing...");
                }
                conceal(cblk, curbp);
            }
        }
        return cblk;
    }

    public DataBlk getInternCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        return getCodeBlock(c, m, n, sb, cblk);
    }

    private boolean sigProgPass(DataBlk cblk, MQDecoder mq, int bp, int[] state, int[] zc_lut, boolean isterm) {
        int dscanw = cblk.scanw;
        int sscanw = cblk.f39w + 2;
        int jstep = ((sscanw * 4) / 2) - cblk.f39w;
        int kstep = (dscanw * 4) - cblk.f39w;
        int setmask = (3 << bp) >> 1;
        int[] data = (int[]) cblk.getData();
        int nstripes = ((cblk.f38h + 4) - 1) / 4;
        boolean causal = (this.options & 8) != 0;
        int off_ul = (-sscanw) - 1;
        int off_ur = (-sscanw) + 1;
        int off_dr = sscanw + 1;
        int off_dl = sscanw - 1;
        int sk = cblk.offset;
        int sj = sscanw + 1;
        int s = nstripes - 1;
        while (s >= 0) {
            int sheight;
            if (s != 0) {
                sheight = 4;
            } else {
                sheight = cblk.f38h - ((nstripes - 1) * 4);
            }
            int stopsk = sk + cblk.f39w;
            while (sk < stopsk) {
                int k;
                int ctxt;
                int sym;
                int i;
                int j = sj;
                int csj = state[j];
                if ((((csj ^ -1) & (csj << 2)) & SIG_MASK_R1R2) != 0) {
                    k = sk;
                    if ((40960 & csj) == 8192) {
                        if (mq.decodeSymbol(zc_lut[csj & 255]) != 0) {
                            ctxt = SC_LUT[(csj >>> 4) & 511];
                            sym = mq.decodeSymbol(ctxt & 15) ^ (ctxt >>> 31);
                            data[k] = (sym << 31) | setmask;
                            if (!causal) {
                                i = j + off_ul;
                                state[i] = state[i] | 536936448;
                                i = j + off_ur;
                                state[i] = state[i] | 537001984;
                            }
                            if (sym != 0) {
                                csj |= 606126080;
                                if (!causal) {
                                    i = j - sscanw;
                                    state[i] = state[i] | 571473920;
                                }
                                i = j + 1;
                                state[i] = state[i] | 537407616;
                                i = j - 1;
                                state[i] = state[i] | 537143360;
                            } else {
                                csj |= 539017216;
                                if (!causal) {
                                    i = j - sscanw;
                                    state[i] = state[i] | 537919488;
                                }
                                i = j + 1;
                                state[i] = state[i] | 537403520;
                                i = j - 1;
                                state[i] = state[i] | 537141312;
                            }
                        } else {
                            csj |= 16384;
                        }
                    }
                    if (sheight < 2) {
                        state[j] = csj;
                        sk++;
                        sj++;
                    } else {
                        if ((-1610612736 & csj) == 536870912) {
                            k += dscanw;
                            if (mq.decodeSymbol(zc_lut[(csj >>> 16) & 255]) != 0) {
                                ctxt = SC_LUT[(csj >>> 20) & 511];
                                sym = mq.decodeSymbol(ctxt & 15) ^ (ctxt >>> 31);
                                data[k] = (sym << 31) | setmask;
                                i = j + off_dl;
                                state[i] = state[i] | 8196;
                                i = j + off_dr;
                                state[i] = state[i] | 8200;
                                if (sym != 0) {
                                    csj |= -1073733104;
                                    i = j + sscanw;
                                    state[i] = state[i] | 9248;
                                    i = j + 1;
                                    state[i] = state[i] | 813703170;
                                    i = j - 1;
                                    state[i] = state[i] | 675291137;
                                } else {
                                    csj |= -1073733616;
                                    i = j + sscanw;
                                    state[i] = state[i] | 8224;
                                    i = j + 1;
                                    state[i] = state[i] | 545267714;
                                    i = j - 1;
                                    state[i] = state[i] | 541073409;
                                }
                            } else {
                                csj |= 1073741824;
                            }
                        }
                        state[j] = csj;
                    }
                }
                if (sheight >= 3) {
                    j += sscanw;
                    csj = state[j];
                    if ((((csj ^ -1) & (csj << 2)) & SIG_MASK_R1R2) != 0) {
                        k = sk + (dscanw << 1);
                        if ((40960 & csj) == 8192) {
                            if (mq.decodeSymbol(zc_lut[csj & 255]) != 0) {
                                ctxt = SC_LUT[(csj >>> 4) & 511];
                                sym = mq.decodeSymbol(ctxt & 15) ^ (ctxt >>> 31);
                                data[k] = (sym << 31) | setmask;
                                i = j + off_ul;
                                state[i] = state[i] | 536936448;
                                i = j + off_ur;
                                state[i] = state[i] | 537001984;
                                if (sym != 0) {
                                    csj |= 606126080;
                                    i = j - sscanw;
                                    state[i] = state[i] | 571473920;
                                    i = j + 1;
                                    state[i] = state[i] | 537407616;
                                    i = j - 1;
                                    state[i] = state[i] | 537143360;
                                } else {
                                    csj |= 539017216;
                                    i = j - sscanw;
                                    state[i] = state[i] | 537919488;
                                    i = j + 1;
                                    state[i] = state[i] | 537403520;
                                    i = j - 1;
                                    state[i] = state[i] | 537141312;
                                }
                            } else {
                                csj |= 16384;
                            }
                        }
                        if (sheight < 4) {
                            state[j] = csj;
                        } else {
                            if ((-1610612736 & csj) == 536870912) {
                                k += dscanw;
                                if (mq.decodeSymbol(zc_lut[(csj >>> 16) & 255]) != 0) {
                                    ctxt = SC_LUT[(csj >>> 20) & 511];
                                    sym = mq.decodeSymbol(ctxt & 15) ^ (ctxt >>> 31);
                                    data[k] = (sym << 31) | setmask;
                                    i = j + off_dl;
                                    state[i] = state[i] | 8196;
                                    i = j + off_dr;
                                    state[i] = state[i] | 8200;
                                    if (sym != 0) {
                                        csj |= -1073733104;
                                        i = j + sscanw;
                                        state[i] = state[i] | 9248;
                                        i = j + 1;
                                        state[i] = state[i] | 813703170;
                                        i = j - 1;
                                        state[i] = state[i] | 675291137;
                                    } else {
                                        csj |= -1073733616;
                                        i = j + sscanw;
                                        state[i] = state[i] | 8224;
                                        i = j + 1;
                                        state[i] = state[i] | 545267714;
                                        i = j - 1;
                                        state[i] = state[i] | 541073409;
                                    }
                                } else {
                                    csj |= 1073741824;
                                }
                            }
                            state[j] = csj;
                        }
                    }
                }
                sk++;
                sj++;
            }
            s--;
            sk += kstep;
            sj += jstep;
        }
        boolean error = false;
        if (isterm && (this.options & 16) != 0) {
            error = mq.checkPredTerm();
        }
        if ((this.options & 2) != 0) {
            mq.resetCtxts();
        }
        return error;
    }

    private boolean rawSigProgPass(DataBlk cblk, ByteToBitInput bin, int bp, int[] state, boolean isterm) {
        int dscanw = cblk.scanw;
        int sscanw = cblk.f39w + 2;
        int jstep = ((sscanw * 4) / 2) - cblk.f39w;
        int kstep = (dscanw * 4) - cblk.f39w;
        int setmask = (3 << bp) >> 1;
        int[] data = (int[]) cblk.getData();
        int nstripes = ((cblk.f38h + 4) - 1) / 4;
        boolean causal = (this.options & 8) != 0;
        int off_ul = (-sscanw) - 1;
        int off_ur = (-sscanw) + 1;
        int off_dr = sscanw + 1;
        int off_dl = sscanw - 1;
        int sk = cblk.offset;
        int sj = sscanw + 1;
        int s = nstripes - 1;
        while (s >= 0) {
            int sheight;
            if (s != 0) {
                sheight = 4;
            } else {
                sheight = cblk.f38h - ((nstripes - 1) * 4);
            }
            int stopsk = sk + cblk.f39w;
            while (sk < stopsk) {
                int k;
                int sym;
                int i;
                int j = sj;
                int csj = state[j];
                if ((((csj ^ -1) & (csj << 2)) & SIG_MASK_R1R2) != 0) {
                    k = sk;
                    if ((40960 & csj) == 8192) {
                        if (bin.readBit() != 0) {
                            sym = bin.readBit();
                            data[k] = (sym << 31) | setmask;
                            if (!causal) {
                                i = j + off_ul;
                                state[i] = state[i] | 536936448;
                                i = j + off_ur;
                                state[i] = state[i] | 537001984;
                            }
                            if (sym != 0) {
                                csj |= 606126080;
                                if (!causal) {
                                    i = j - sscanw;
                                    state[i] = state[i] | 571473920;
                                }
                                i = j + 1;
                                state[i] = state[i] | 537407616;
                                i = j - 1;
                                state[i] = state[i] | 537143360;
                            } else {
                                csj |= 539017216;
                                if (!causal) {
                                    i = j - sscanw;
                                    state[i] = state[i] | 537919488;
                                }
                                i = j + 1;
                                state[i] = state[i] | 537403520;
                                i = j - 1;
                                state[i] = state[i] | 537141312;
                            }
                        } else {
                            csj |= 16384;
                        }
                    }
                    if (sheight < 2) {
                        state[j] = csj;
                        sk++;
                        sj++;
                    } else {
                        if ((-1610612736 & csj) == 536870912) {
                            k += dscanw;
                            if (bin.readBit() != 0) {
                                sym = bin.readBit();
                                data[k] = (sym << 31) | setmask;
                                i = j + off_dl;
                                state[i] = state[i] | 8196;
                                i = j + off_dr;
                                state[i] = state[i] | 8200;
                                if (sym != 0) {
                                    csj |= -1073733104;
                                    i = j + sscanw;
                                    state[i] = state[i] | 9248;
                                    i = j + 1;
                                    state[i] = state[i] | 813703170;
                                    i = j - 1;
                                    state[i] = state[i] | 675291137;
                                } else {
                                    csj |= -1073733616;
                                    i = j + sscanw;
                                    state[i] = state[i] | 8224;
                                    i = j + 1;
                                    state[i] = state[i] | 545267714;
                                    i = j - 1;
                                    state[i] = state[i] | 541073409;
                                }
                            } else {
                                csj |= 1073741824;
                            }
                        }
                        state[j] = csj;
                    }
                }
                if (sheight >= 3) {
                    j += sscanw;
                    csj = state[j];
                    if ((((csj ^ -1) & (csj << 2)) & SIG_MASK_R1R2) != 0) {
                        k = sk + (dscanw << 1);
                        if ((40960 & csj) == 8192) {
                            if (bin.readBit() != 0) {
                                sym = bin.readBit();
                                data[k] = (sym << 31) | setmask;
                                i = j + off_ul;
                                state[i] = state[i] | 536936448;
                                i = j + off_ur;
                                state[i] = state[i] | 537001984;
                                if (sym != 0) {
                                    csj |= 606126080;
                                    i = j - sscanw;
                                    state[i] = state[i] | 571473920;
                                    i = j + 1;
                                    state[i] = state[i] | 537407616;
                                    i = j - 1;
                                    state[i] = state[i] | 537143360;
                                } else {
                                    csj |= 539017216;
                                    i = j - sscanw;
                                    state[i] = state[i] | 537919488;
                                    i = j + 1;
                                    state[i] = state[i] | 537403520;
                                    i = j - 1;
                                    state[i] = state[i] | 537141312;
                                }
                            } else {
                                csj |= 16384;
                            }
                        }
                        if (sheight < 4) {
                            state[j] = csj;
                        } else {
                            if ((-1610612736 & csj) == 536870912) {
                                k += dscanw;
                                if (bin.readBit() != 0) {
                                    sym = bin.readBit();
                                    data[k] = (sym << 31) | setmask;
                                    i = j + off_dl;
                                    state[i] = state[i] | 8196;
                                    i = j + off_dr;
                                    state[i] = state[i] | 8200;
                                    if (sym != 0) {
                                        csj |= -1073733104;
                                        i = j + sscanw;
                                        state[i] = state[i] | 9248;
                                        i = j + 1;
                                        state[i] = state[i] | 813703170;
                                        i = j - 1;
                                        state[i] = state[i] | 675291137;
                                    } else {
                                        csj |= -1073733616;
                                        i = j + sscanw;
                                        state[i] = state[i] | 8224;
                                        i = j + 1;
                                        state[i] = state[i] | 545267714;
                                        i = j - 1;
                                        state[i] = state[i] | 541073409;
                                    }
                                } else {
                                    csj |= 1073741824;
                                }
                            }
                            state[j] = csj;
                        }
                    }
                }
                sk++;
                sj++;
            }
            s--;
            sk += kstep;
            sj += jstep;
        }
        if (!isterm || (this.options & 16) == 0) {
            return false;
        }
        return bin.checkBytePadding();
    }

    private boolean magRefPass(DataBlk cblk, MQDecoder mq, int bp, int[] state, boolean isterm) {
        int dscanw = cblk.scanw;
        int sscanw = cblk.f39w + 2;
        int jstep = ((sscanw * 4) / 2) - cblk.f39w;
        int kstep = (dscanw * 4) - cblk.f39w;
        int setmask = (1 << bp) >> 1;
        int resetmask = -1 << (bp + 1);
        int[] data = (int[]) cblk.getData();
        int nstripes = ((cblk.f38h + 4) - 1) / 4;
        int sk = cblk.offset;
        int sj = sscanw + 1;
        int s = nstripes - 1;
        while (s >= 0) {
            int sheight;
            if (s != 0) {
                sheight = 4;
            } else {
                sheight = cblk.f38h - ((nstripes - 1) * 4);
            }
            int stopsk = sk + cblk.f39w;
            while (sk < stopsk) {
                int k;
                int sym;
                int j = sj;
                int csj = state[j];
                if ((((csj >>> 1) & (csj ^ -1)) & VSTD_MASK_R1R2) != 0) {
                    k = sk;
                    if ((49152 & csj) == 32768) {
                        sym = mq.decodeSymbol(MR_LUT[csj & 511]);
                        data[k] = data[k] & resetmask;
                        data[k] = data[k] | ((sym << bp) | setmask);
                        csj |= 256;
                    }
                    if (sheight < 2) {
                        state[j] = csj;
                        sk++;
                        sj++;
                    } else {
                        if ((-1073741824 & csj) == Integer.MIN_VALUE) {
                            k += dscanw;
                            sym = mq.decodeSymbol(MR_LUT[(csj >>> 16) & 511]);
                            data[k] = data[k] & resetmask;
                            data[k] = data[k] | ((sym << bp) | setmask);
                            csj |= STATE_PREV_MR_R2;
                        }
                        state[j] = csj;
                    }
                }
                if (sheight >= 3) {
                    j += sscanw;
                    csj = state[j];
                    if ((((csj >>> 1) & (csj ^ -1)) & VSTD_MASK_R1R2) != 0) {
                        k = sk + (dscanw << 1);
                        if ((49152 & csj) == 32768) {
                            sym = mq.decodeSymbol(MR_LUT[csj & 511]);
                            data[k] = data[k] & resetmask;
                            data[k] = data[k] | ((sym << bp) | setmask);
                            csj |= 256;
                        }
                        if (sheight < 4) {
                            state[j] = csj;
                        } else {
                            if ((state[j] & -1073741824) == Integer.MIN_VALUE) {
                                k += dscanw;
                                sym = mq.decodeSymbol(MR_LUT[(csj >>> 16) & 511]);
                                data[k] = data[k] & resetmask;
                                data[k] = data[k] | ((sym << bp) | setmask);
                                csj |= STATE_PREV_MR_R2;
                            }
                            state[j] = csj;
                        }
                    }
                }
                sk++;
                sj++;
            }
            s--;
            sk += kstep;
            sj += jstep;
        }
        boolean error = false;
        if (isterm && (this.options & 16) != 0) {
            error = mq.checkPredTerm();
        }
        if ((this.options & 2) != 0) {
            mq.resetCtxts();
        }
        return error;
    }

    private boolean rawMagRefPass(DataBlk cblk, ByteToBitInput bin, int bp, int[] state, boolean isterm) {
        int dscanw = cblk.scanw;
        int sscanw = cblk.f39w + 2;
        int jstep = ((sscanw * 4) / 2) - cblk.f39w;
        int kstep = (dscanw * 4) - cblk.f39w;
        int setmask = (1 << bp) >> 1;
        int resetmask = -1 << (bp + 1);
        int[] data = (int[]) cblk.getData();
        int nstripes = ((cblk.f38h + 4) - 1) / 4;
        int sk = cblk.offset;
        int sj = sscanw + 1;
        int s = nstripes - 1;
        while (s >= 0) {
            int sheight;
            if (s != 0) {
                sheight = 4;
            } else {
                sheight = cblk.f38h - ((nstripes - 1) * 4);
            }
            int stopsk = sk + cblk.f39w;
            while (sk < stopsk) {
                int k;
                int sym;
                int j = sj;
                int csj = state[j];
                if ((((csj >>> 1) & (csj ^ -1)) & VSTD_MASK_R1R2) != 0) {
                    k = sk;
                    if ((49152 & csj) == 32768) {
                        sym = bin.readBit();
                        data[k] = data[k] & resetmask;
                        data[k] = data[k] | ((sym << bp) | setmask);
                    }
                    if (sheight < 2) {
                        sk++;
                        sj++;
                    } else if ((-1073741824 & csj) == Integer.MIN_VALUE) {
                        k += dscanw;
                        sym = bin.readBit();
                        data[k] = data[k] & resetmask;
                        data[k] = data[k] | ((sym << bp) | setmask);
                    }
                }
                if (sheight >= 3) {
                    j += sscanw;
                    csj = state[j];
                    if ((((csj >>> 1) & (csj ^ -1)) & VSTD_MASK_R1R2) != 0) {
                        k = sk + (dscanw << 1);
                        if ((49152 & csj) == 32768) {
                            sym = bin.readBit();
                            data[k] = data[k] & resetmask;
                            data[k] = data[k] | ((sym << bp) | setmask);
                        }
                        if (sheight >= 4 && (state[j] & -1073741824) == Integer.MIN_VALUE) {
                            k += dscanw;
                            sym = bin.readBit();
                            data[k] = data[k] & resetmask;
                            data[k] = data[k] | ((sym << bp) | setmask);
                        }
                    }
                }
                sk++;
                sj++;
            }
            s--;
            sk += kstep;
            sj += jstep;
        }
        if (!isterm || (this.options & 16) == 0) {
            return false;
        }
        return bin.checkBytePadding();
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private boolean cleanuppass(jj2000.j2k.image.DataBlk r32, jj2000.j2k.entropy.decoder.MQDecoder r33, int r34, int[] r35, int[] r36, boolean r37) {
        /*
        r31 = this;
        r0 = r32;
        r6 = r0.scanw;
        r0 = r32;
        r0 = r0.f39w;
        r28 = r0;
        r25 = r28 + 2;
        r28 = r25 * 4;
        r28 = r28 / 2;
        r0 = r32;
        r0 = r0.f39w;
        r29 = r0;
        r10 = r28 - r29;
        r28 = r6 * 4;
        r0 = r32;
        r0 = r0.f39w;
        r29 = r0;
        r12 = r28 - r29;
        r28 = 1;
        r18 = r28 << r34;
        r8 = r18 >> 1;
        r21 = r18 | r8;
        r28 = r32.getData();
        r28 = (int[]) r28;
        r5 = r28;
        r5 = (int[]) r5;
        r0 = r32;
        r0 = r0.f38h;
        r28 = r0;
        r28 = r28 + 4;
        r28 = r28 + -1;
        r13 = r28 / 4;
        r0 = r31;
        r0 = r0.options;
        r28 = r0;
        r28 = r28 & 8;
        if (r28 == 0) goto L_0x01cb;
    L_0x004a:
        r2 = 1;
    L_0x004b:
        r0 = r25;
        r0 = -r0;
        r28 = r0;
        r16 = r28 + -1;
        r0 = r25;
        r0 = -r0;
        r28 = r0;
        r17 = r28 + 1;
        r15 = r25 + 1;
        r14 = r25 + -1;
        r0 = r32;
        r0 = r0.offset;
        r24 = r0;
        r23 = r25 + 1;
        r20 = r13 + -1;
    L_0x0067:
        if (r20 < 0) goto L_0x04f4;
    L_0x0069:
        if (r20 == 0) goto L_0x01ce;
    L_0x006b:
        r22 = 4;
    L_0x006d:
        r0 = r32;
        r0 = r0.f39w;
        r28 = r0;
        r26 = r24 + r28;
    L_0x0075:
        r0 = r24;
        r1 = r26;
        if (r0 >= r1) goto L_0x04ec;
    L_0x007b:
        r9 = r23;
        r3 = r35[r9];
        if (r3 != 0) goto L_0x029c;
    L_0x0081:
        r28 = r9 + r25;
        r28 = r35[r28];
        if (r28 != 0) goto L_0x029c;
    L_0x0087:
        r28 = 4;
        r0 = r22;
        r1 = r28;
        if (r0 != r1) goto L_0x029c;
    L_0x008f:
        r28 = 1;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        if (r28 == 0) goto L_0x01c5;
    L_0x009b:
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r19 = r28 << 1;
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r19 = r19 | r28;
        r28 = r19 * r6;
        r11 = r24 + r28;
        r28 = 1;
        r0 = r19;
        r1 = r28;
        if (r0 <= r1) goto L_0x00c3;
    L_0x00bf:
        r9 = r9 + r25;
        r3 = r35[r9];
    L_0x00c3:
        r28 = r19 & 1;
        if (r28 != 0) goto L_0x0207;
    L_0x00c7:
        r28 = SC_LUT;
        r29 = r3 >> 4;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        if (r19 != 0) goto L_0x00eb;
    L_0x00e9:
        if (r2 != 0) goto L_0x00ff;
    L_0x00eb:
        r28 = r9 + r16;
        r29 = r35[r28];
        r30 = 536936448; // 0x20010000 float:1.0926725E-19 double:2.65281853E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + r17;
        r29 = r35[r28];
        r30 = 537001984; // 0x20020000 float:1.1011428E-19 double:2.65314232E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x00ff:
        if (r27 == 0) goto L_0x01dc;
    L_0x0101:
        r28 = 606126080; // 0x2420c000 float:3.48571E-17 double:2.99466073E-315;
        r3 = r3 | r28;
        if (r19 != 0) goto L_0x010a;
    L_0x0108:
        if (r2 != 0) goto L_0x0114;
    L_0x010a:
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 571473920; // 0x22100000 float:1.951564E-18 double:2.823456314E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x0114:
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537407616; // 0x20083080 float:1.1535695E-19 double:2.65514641E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537143360; // 0x20042840 float:1.1194153E-19 double:2.65384081E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x012a:
        r28 = r19 >> 1;
        if (r28 == 0) goto L_0x029c;
    L_0x012e:
        r28 = r3 >> 1;
        r28 = r28 | r3;
        r29 = 1073758208; // 0x40004000 float:2.0039062 double:5.305070425E-315;
        r28 = r28 & r29;
        r29 = 1073758208; // 0x40004000 float:2.0039062 double:5.305070425E-315;
        r0 = r28;
        r1 = r29;
        if (r0 == r1) goto L_0x04bb;
    L_0x0140:
        r28 = r6 << 1;
        r11 = r24 + r28;
        r28 = 49152; // 0xc000 float:6.8877E-41 double:2.42843E-319;
        r28 = r28 & r3;
        if (r28 != 0) goto L_0x01b6;
    L_0x014b:
        r0 = r3 & 255;
        r28 = r0;
        r28 = r36[r28];
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        if (r28 == 0) goto L_0x01b6;
    L_0x015b:
        r28 = SC_LUT;
        r29 = r3 >> 4;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        r28 = r9 + r16;
        r29 = r35[r28];
        r30 = 536936448; // 0x20010000 float:1.0926725E-19 double:2.65281853E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + r17;
        r29 = r35[r28];
        r30 = 537001984; // 0x20020000 float:1.1011428E-19 double:2.65314232E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        if (r27 == 0) goto L_0x0418;
    L_0x0191:
        r28 = 606126080; // 0x2420c000 float:3.48571E-17 double:2.99466073E-315;
        r3 = r3 | r28;
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 571473920; // 0x22100000 float:1.951564E-18 double:2.823456314E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537407616; // 0x20083080 float:1.1535695E-19 double:2.65514641E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537143360; // 0x20042840 float:1.1194153E-19 double:2.65384081E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x01b6:
        r28 = 4;
        r0 = r22;
        r1 = r28;
        if (r0 >= r1) goto L_0x043f;
    L_0x01be:
        r28 = -1073758209; // 0xffffffffbfffbfff float:-1.9980468 double:NaN;
        r3 = r3 & r28;
        r35[r9] = r3;
    L_0x01c5:
        r24 = r24 + 1;
        r23 = r23 + 1;
        goto L_0x0075;
    L_0x01cb:
        r2 = 0;
        goto L_0x004b;
    L_0x01ce:
        r0 = r32;
        r0 = r0.f38h;
        r28 = r0;
        r29 = r13 + -1;
        r29 = r29 * 4;
        r22 = r28 - r29;
        goto L_0x006d;
    L_0x01dc:
        r28 = 539017216; // 0x2020c000 float:1.3616055E-19 double:2.66309889E-315;
        r3 = r3 | r28;
        if (r19 != 0) goto L_0x01e5;
    L_0x01e3:
        if (r2 != 0) goto L_0x01ef;
    L_0x01e5:
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 537919488; // 0x20100000 float:1.2197274E-19 double:2.657675392E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x01ef:
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537403520; // 0x20082080 float:1.1530401E-19 double:2.65512617E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537141312; // 0x20042040 float:1.1191506E-19 double:2.65383069E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x012a;
    L_0x0207:
        r28 = SC_LUT;
        r29 = r3 >> 20;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        r28 = r9 + r14;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8196;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + r15;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8200;
        r29 = r0;
        r35[r28] = r29;
        if (r27 == 0) goto L_0x0274;
    L_0x0241:
        r28 = -2147474928; // 0xffffffff80002210 float:-1.222E-41 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 9248;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 813703170; // 0x30802002 float:9.322323E-10 double:4.02022782E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 675291137; // 0x28402001 float:1.0665081E-14 double:3.336381517E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x0268:
        r35[r9] = r3;
        r28 = r19 >> 1;
        if (r28 != 0) goto L_0x01c5;
    L_0x026e:
        r9 = r9 + r25;
        r3 = r35[r9];
        goto L_0x012e;
    L_0x0274:
        r28 = -2147475440; // 0xffffffff80002010 float:-1.1502E-41 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8224;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 545267714; // 0x20802002 float:2.1705224E-19 double:2.693980453E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 541073409; // 0x20402001 float:1.6273622E-19 double:2.673257833E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x0268;
    L_0x029c:
        r28 = r3 >> 1;
        r28 = r28 | r3;
        r29 = 1073758208; // 0x40004000 float:2.0039062 double:5.305070425E-315;
        r28 = r28 & r29;
        r29 = 1073758208; // 0x40004000 float:2.0039062 double:5.305070425E-315;
        r0 = r28;
        r1 = r29;
        if (r0 == r1) goto L_0x03db;
    L_0x02ae:
        r11 = r24;
        r28 = 49152; // 0xc000 float:6.8877E-41 double:2.42843E-319;
        r28 = r28 & r3;
        if (r28 != 0) goto L_0x0326;
    L_0x02b7:
        r0 = r3 & 255;
        r28 = r0;
        r28 = r36[r28];
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        if (r28 == 0) goto L_0x0326;
    L_0x02c7:
        r28 = SC_LUT;
        r29 = r3 >>> 4;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        if (r2 != 0) goto L_0x02fd;
    L_0x02e9:
        r28 = r9 + r16;
        r29 = r35[r28];
        r30 = 536936448; // 0x20010000 float:1.0926725E-19 double:2.65281853E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + r17;
        r29 = r35[r28];
        r30 = 537001984; // 0x20020000 float:1.1011428E-19 double:2.65314232E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x02fd:
        if (r27 == 0) goto L_0x0337;
    L_0x02ff:
        r28 = 606126080; // 0x2420c000 float:3.48571E-17 double:2.99466073E-315;
        r3 = r3 | r28;
        if (r2 != 0) goto L_0x0310;
    L_0x0306:
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 571473920; // 0x22100000 float:1.951564E-18 double:2.823456314E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x0310:
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537407616; // 0x20083080 float:1.1535695E-19 double:2.65514641E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537143360; // 0x20042840 float:1.1194153E-19 double:2.65384081E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x0326:
        r28 = 2;
        r0 = r22;
        r1 = r28;
        if (r0 >= r1) goto L_0x035f;
    L_0x032e:
        r28 = -1073758209; // 0xffffffffbfffbfff float:-1.9980468 double:NaN;
        r3 = r3 & r28;
        r35[r9] = r3;
        goto L_0x01c5;
    L_0x0337:
        r28 = 539017216; // 0x2020c000 float:1.3616055E-19 double:2.66309889E-315;
        r3 = r3 | r28;
        if (r2 != 0) goto L_0x0348;
    L_0x033e:
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 537919488; // 0x20100000 float:1.2197274E-19 double:2.657675392E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x0348:
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537403520; // 0x20082080 float:1.1530401E-19 double:2.65512617E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537141312; // 0x20042040 float:1.1191506E-19 double:2.65383069E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x0326;
    L_0x035f:
        r28 = -1073741824; // 0xffffffffc0000000 float:-2.0 double:NaN;
        r28 = r28 & r3;
        if (r28 != 0) goto L_0x03db;
    L_0x0365:
        r11 = r11 + r6;
        r28 = r3 >>> 16;
        r0 = r28;
        r0 = r0 & 255;
        r28 = r0;
        r28 = r36[r28];
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        if (r28 == 0) goto L_0x03db;
    L_0x037a:
        r28 = SC_LUT;
        r29 = r3 >>> 20;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        r28 = r9 + r14;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8196;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + r15;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8200;
        r29 = r0;
        r35[r28] = r29;
        if (r27 == 0) goto L_0x03f0;
    L_0x03b4:
        r28 = -1073733104; // 0xffffffffc0002210 float:-2.002079 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 9248;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 813703170; // 0x30802002 float:9.322323E-10 double:4.02022782E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 675291137; // 0x28402001 float:1.0665081E-14 double:3.336381517E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x03db:
        r28 = -1073758209; // 0xffffffffbfffbfff float:-1.9980468 double:NaN;
        r3 = r3 & r28;
        r35[r9] = r3;
        r28 = 3;
        r0 = r22;
        r1 = r28;
        if (r0 < r1) goto L_0x01c5;
    L_0x03ea:
        r9 = r9 + r25;
        r3 = r35[r9];
        goto L_0x012e;
    L_0x03f0:
        r28 = -1073733616; // 0xffffffffc0002010 float:-2.001957 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8224;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 545267714; // 0x20802002 float:2.1705224E-19 double:2.693980453E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 541073409; // 0x20402001 float:1.6273622E-19 double:2.673257833E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x03db;
    L_0x0418:
        r28 = 539017216; // 0x2020c000 float:1.3616055E-19 double:2.66309889E-315;
        r3 = r3 | r28;
        r28 = r9 - r25;
        r29 = r35[r28];
        r30 = 537919488; // 0x20100000 float:1.2197274E-19 double:2.657675392E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 537403520; // 0x20082080 float:1.1530401E-19 double:2.65512617E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 537141312; // 0x20042040 float:1.1191506E-19 double:2.65383069E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x01b6;
    L_0x043f:
        r28 = -1073741824; // 0xffffffffc0000000 float:-2.0 double:NaN;
        r28 = r28 & r3;
        if (r28 != 0) goto L_0x04bb;
    L_0x0445:
        r11 = r11 + r6;
        r28 = r3 >>> 16;
        r0 = r28;
        r0 = r0 & 255;
        r28 = r0;
        r28 = r36[r28];
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        if (r28 == 0) goto L_0x04bb;
    L_0x045a:
        r28 = SC_LUT;
        r29 = r3 >>> 20;
        r0 = r29;
        r0 = r0 & 511;
        r29 = r0;
        r4 = r28[r29];
        r28 = r4 & 15;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r29 = r4 >>> 31;
        r27 = r28 ^ r29;
        r28 = r27 << 31;
        r28 = r28 | r21;
        r5[r11] = r28;
        r28 = r9 + r14;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8196;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + r15;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8200;
        r29 = r0;
        r35[r28] = r29;
        if (r27 == 0) goto L_0x04c4;
    L_0x0494:
        r28 = -1073733104; // 0xffffffffc0002210 float:-2.002079 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 9248;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 813703170; // 0x30802002 float:9.322323E-10 double:4.02022782E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 675291137; // 0x28402001 float:1.0665081E-14 double:3.336381517E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
    L_0x04bb:
        r28 = -1073758209; // 0xffffffffbfffbfff float:-1.9980468 double:NaN;
        r3 = r3 & r28;
        r35[r9] = r3;
        goto L_0x01c5;
    L_0x04c4:
        r28 = -1073733616; // 0xffffffffc0002010 float:-2.001957 double:NaN;
        r3 = r3 | r28;
        r28 = r9 + r25;
        r29 = r35[r28];
        r0 = r29;
        r0 = r0 | 8224;
        r29 = r0;
        r35[r28] = r29;
        r28 = r9 + 1;
        r29 = r35[r28];
        r30 = 545267714; // 0x20802002 float:2.1705224E-19 double:2.693980453E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        r28 = r9 + -1;
        r29 = r35[r28];
        r30 = 541073409; // 0x20402001 float:1.6273622E-19 double:2.673257833E-315;
        r29 = r29 | r30;
        r35[r28] = r29;
        goto L_0x04bb;
    L_0x04ec:
        r20 = r20 + -1;
        r24 = r24 + r12;
        r23 = r23 + r10;
        goto L_0x0067;
    L_0x04f4:
        r0 = r31;
        r0 = r0.options;
        r28 = r0;
        r28 = r28 & 32;
        if (r28 == 0) goto L_0x055b;
    L_0x04fe:
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r27 = r28 << 3;
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r28 = r28 << 2;
        r27 = r27 | r28;
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r28 = r28 << 1;
        r27 = r27 | r28;
        r28 = 0;
        r0 = r33;
        r1 = r28;
        r28 = r0.decodeSymbol(r1);
        r27 = r27 | r28;
        r28 = 10;
        r0 = r27;
        r1 = r28;
        if (r0 == r1) goto L_0x0559;
    L_0x053a:
        r7 = 1;
    L_0x053b:
        if (r37 == 0) goto L_0x054b;
    L_0x053d:
        r0 = r31;
        r0 = r0.options;
        r28 = r0;
        r28 = r28 & 16;
        if (r28 == 0) goto L_0x054b;
    L_0x0547:
        r7 = r33.checkPredTerm();
    L_0x054b:
        r0 = r31;
        r0 = r0.options;
        r28 = r0;
        r28 = r28 & 2;
        if (r28 == 0) goto L_0x0558;
    L_0x0555:
        r33.resetCtxts();
    L_0x0558:
        return r7;
    L_0x0559:
        r7 = 0;
        goto L_0x053b;
    L_0x055b:
        r7 = 0;
        goto L_0x053b;
        */
        throw new UnsupportedOperationException("Method not decompiled: jj2000.j2k.entropy.decoder.StdEntropyDecoder.cleanuppass(jj2000.j2k.image.DataBlk, jj2000.j2k.entropy.decoder.MQDecoder, int, int[], int[], boolean):boolean");
    }

    private void conceal(DataBlk cblk, int bp) {
        int setmask = 1 << bp;
        int resetmask = -1 << bp;
        int[] data = (int[]) cblk.getData();
        int k = cblk.offset;
        for (int l = cblk.f38h - 1; l >= 0; l--) {
            int kmax = k + cblk.f39w;
            while (k < kmax) {
                int dk = data[k];
                if (((dk & resetmask) & Integer.MAX_VALUE) != 0) {
                    data[k] = (dk & resetmask) | setmask;
                } else {
                    data[k] = 0;
                }
                k++;
            }
            k += cblk.scanw - cblk.f39w;
        }
    }
}
