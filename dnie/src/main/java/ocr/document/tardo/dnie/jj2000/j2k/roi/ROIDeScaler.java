package jj2000.j2k.roi;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.quantization.dequantizer.CBlkQuantDataSrcDec;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.MultiResImgDataAdapter;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public class ROIDeScaler extends MultiResImgDataAdapter implements CBlkQuantDataSrcDec {
    public static final char OPT_PREFIX = 'R';
    private static final String[][] pinfo;
    private MaxShiftSpec mss;
    private CBlkQuantDataSrcDec src;

    static {
        String[][] strArr = new String[1][];
        strArr[0] = new String[]{"Rno_roi", null, "This argument makes sure that the no ROI de-scaling is performed. Decompression is done like there is no ROI in the image", null};
        pinfo = strArr;
    }

    public ROIDeScaler(CBlkQuantDataSrcDec src, MaxShiftSpec mss) {
        super(src);
        this.src = src;
        this.mss = mss;
    }

    public SubbandSyn getSynSubbandTree(int t, int c) {
        return this.src.getSynSubbandTree(t, c);
    }

    public int getCbULX() {
        return this.src.getCbULX();
    }

    public int getCbULY() {
        return this.src.getCbULY();
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    public DataBlk getCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        return getInternCodeBlock(c, m, n, sb, cblk);
    }

    public DataBlk getInternCodeBlock(int c, int m, int n, SubbandSyn sb, DataBlk cblk) {
        cblk = this.src.getInternCodeBlock(c, m, n, sb, cblk);
        boolean noRoiInTile = false;
        if (this.mss == null || this.mss.getTileCompVal(getTileIdx(), c) == null) {
            noRoiInTile = true;
        }
        if (!(noRoiInTile || cblk == null)) {
            int[] data = (int[]) cblk.getData();
            int ulx = cblk.ulx;
            int uly = cblk.uly;
            int w = cblk.f39w;
            int h = cblk.f38h;
            int boost = ((Integer) this.mss.getTileCompVal(getTileIdx(), c)).intValue();
            int mask = ((1 << sb.magbits) - 1) << (31 - sb.magbits);
            int mask2 = (mask ^ -1) & Integer.MAX_VALUE;
            int wrap = cblk.scanw - w;
            int i = ((cblk.offset + (cblk.scanw * (h - 1))) + w) - 1;
            for (int j = h; j > 0; j--) {
                int k = w;
                while (k > 0) {
                    int tmp = data[i];
                    if ((tmp & mask) == 0) {
                        data[i] = (Integer.MIN_VALUE & tmp) | (tmp << boost);
                    } else if ((tmp & mask2) != 0) {
                        data[i] = ((mask2 ^ -1) & tmp) | (1 << (30 - sb.magbits));
                    }
                    k--;
                    i--;
                }
                i -= wrap;
            }
        }
        return cblk;
    }

    public static ROIDeScaler createInstance(CBlkQuantDataSrcDec src, ParameterList pl, DecoderSpecs decSpec) {
        pl.checkList('R', ParameterList.toNameArray(pinfo));
        if (pl.getParameter("Rno_roi") != null || decSpec.rois == null) {
            return new ROIDeScaler(src, null);
        }
        return new ROIDeScaler(src, decSpec.rois);
    }
}
