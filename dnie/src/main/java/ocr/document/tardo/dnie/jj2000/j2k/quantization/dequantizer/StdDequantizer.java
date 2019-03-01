package jj2000.j2k.quantization.dequantizer;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.quantization.GuardBitsSpec;
import jj2000.j2k.quantization.QuantStepSizeSpec;
import jj2000.j2k.quantization.QuantTypeSpec;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public class StdDequantizer extends Dequantizer {
    private GuardBitsSpec gbs;
    private DataBlkInt inblk;
    private int outdtype;
    private StdDequantizerParams params;
    private QuantStepSizeSpec qsss;
    private QuantTypeSpec qts;

    public StdDequantizer(CBlkQuantDataSrcDec src, int[] utrb, DecoderSpecs decSpec) {
        super(src, utrb, decSpec);
        if (utrb.length != src.getNumComps()) {
            throw new IllegalArgumentException("Invalid rb argument");
        }
        this.qsss = decSpec.qsss;
        this.qts = decSpec.qts;
        this.gbs = decSpec.gbs;
    }

    public int getFixedPoint(int c) {
        return 0;
    }

    public final DataBlk getCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        return getInternCodeBlock(c, m, n, sb, cblk);
    }

    public final DataBlk getInternCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        boolean reversible = this.qts.isReversible(this.tIdx, c);
        boolean derived = this.qts.isDerived(this.tIdx, c);
        StdDequantizerParams params = (StdDequantizerParams) this.qsss.getTileCompVal(this.tIdx, c);
        int G = ((Integer) this.gbs.getTileCompVal(this.tIdx, c)).intValue();
        this.outdtype = cblk.getDataType();
        if (!reversible || this.outdtype == 3) {
            int[] outiarr = null;
            float[] outfarr = null;
            int[] inarr = null;
            switch (this.outdtype) {
                case 3:
                    cblk = this.src.getCodeBlock(c, m, n, sb, cblk);
                    outiarr = (int[]) cblk.getData();
                    break;
                case 4:
                    this.inblk = (DataBlkInt) this.src.getInternCodeBlock(c, m, n, sb, this.inblk);
                    inarr = this.inblk.getDataInt();
                    if (cblk == null) {
                        cblk = new DataBlkFloat();
                    }
                    cblk.ulx = this.inblk.ulx;
                    cblk.uly = this.inblk.uly;
                    cblk.f39w = this.inblk.w;
                    cblk.f38h = this.inblk.h;
                    cblk.offset = 0;
                    cblk.scanw = cblk.f39w;
                    cblk.progressive = this.inblk.progressive;
                    outfarr = (float[]) cblk.getData();
                    if (outfarr == null || outfarr.length < cblk.f39w * cblk.f38h) {
                        Object outfarr2 = new float[(cblk.f39w * cblk.f38h)];
                        cblk.setData(outfarr2);
                        break;
                    }
            }
            int magBits = sb.magbits;
            int j;
            int temp;
            if (!reversible) {
                float step;
                if (derived) {
                    step = params.nStep[0][0] * ((float) (1 << (((this.rb[c] + sb.anGainExp) + this.src.getSynSubbandTree(getTileIdx(), c).resLvl) - sb.level)));
                } else {
                    step = params.nStep[sb.resLvl][sb.sbandIdx] * ((float) (1 << (this.rb[c] + sb.anGainExp)));
                }
                step /= (float) (1 << (31 - magBits));
                switch (this.outdtype) {
                    case 3:
                        for (j = outiarr.length - 1; j >= 0; j--) {
                            temp = outiarr[j];
                            if (temp < 0) {
                                temp = -(Integer.MAX_VALUE & temp);
                            }
                            outiarr[j] = (int) (((float) temp) * step);
                        }
                        break;
                    case 4:
                        int w = cblk.f39w;
                        int h = cblk.f38h;
                        j = (w * h) - 1;
                        int k = ((this.inblk.offset + ((h - 1) * this.inblk.scanw)) + w) - 1;
                        int jmin = w * (h - 1);
                        while (j >= 0) {
                            while (j >= jmin) {
                                temp = inarr[k];
                                if (temp < 0) {
                                    temp = -(Integer.MAX_VALUE & temp);
                                }
                                outfarr[j] = ((float) temp) * step;
                                k--;
                                j--;
                            }
                            k -= this.inblk.scanw - w;
                            jmin -= w;
                        }
                        break;
                }
            }
            int shiftBits = 31 - magBits;
            for (j = outiarr.length - 1; j >= 0; j--) {
                temp = outiarr[j];
                outiarr[j] = temp >= 0 ? temp >> shiftBits : -((Integer.MAX_VALUE & temp) >> shiftBits);
            }
            return cblk;
        }
        throw new IllegalArgumentException("Reversible quantizations must use int data");
    }
}
