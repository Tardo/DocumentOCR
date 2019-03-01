package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.Coord;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.FacilityManager;
import jj2000.j2k.util.ProgressWatch;
import jj2000.j2k.wavelet.Subband;

public class InvWTFull extends InverseWT {
    private int cblkToDecode = 0;
    private int dtype;
    private int nDecCblk = 0;
    private int[] ndl;
    private ProgressWatch pw = null;
    private DataBlk[] reconstructedComps;
    private boolean[][] reversible;
    private CBlkWTDataSrcDec src;

    public InvWTFull(CBlkWTDataSrcDec src, DecoderSpecs decSpec) {
        super(src, decSpec);
        this.src = src;
        int nc = src.getNumComps();
        this.reconstructedComps = new DataBlk[nc];
        this.ndl = new int[nc];
        this.pw = FacilityManager.getProgressWatch();
    }

    private boolean isSubbandReversible(Subband subband) {
        if (subband.isNode) {
            return isSubbandReversible(subband.getLL()) && isSubbandReversible(subband.getHL()) && isSubbandReversible(subband.getLH()) && isSubbandReversible(subband.getHH()) && ((SubbandSyn) subband).hFilter.isReversible() && ((SubbandSyn) subband).vFilter.isReversible();
        } else {
            return true;
        }
    }

    public boolean isReversible(int t, int c) {
        if (this.reversible[t] == null) {
            this.reversible[t] = new boolean[getNumComps()];
            for (int i = this.reversible.length - 1; i >= 0; i--) {
                this.reversible[t][i] = isSubbandReversible(this.src.getSynSubbandTree(t, i));
            }
        }
        return this.reversible[t][c];
    }

    public int getNomRangeBits(int c) {
        return this.src.getNomRangeBits(c);
    }

    public int getFixedPoint(int c) {
        return this.src.getFixedPoint(c);
    }

    public final DataBlk getInternCompData(DataBlk blk, int c) {
        int tIdx = getTileIdx();
        if (this.src.getSynSubbandTree(tIdx, c).getHorWFilter() == null) {
            this.dtype = 3;
        } else {
            this.dtype = this.src.getSynSubbandTree(tIdx, c).getHorWFilter().getDataType();
        }
        if (this.reconstructedComps[c] == null) {
            switch (this.dtype) {
                case 3:
                    this.reconstructedComps[c] = new DataBlkInt(0, 0, getTileCompWidth(tIdx, c), getTileCompHeight(tIdx, c));
                    break;
                case 4:
                    this.reconstructedComps[c] = new DataBlkFloat(0, 0, getTileCompWidth(tIdx, c), getTileCompHeight(tIdx, c));
                    break;
            }
            waveletTreeReconstruction(this.reconstructedComps[c], this.src.getSynSubbandTree(tIdx, c), c);
            if (this.pw != null && c == this.src.getNumComps() - 1) {
                this.pw.terminateProgressWatch();
            }
        }
        if (blk.getDataType() != this.dtype) {
            if (this.dtype == 3) {
                blk = new DataBlkInt(blk.ulx, blk.uly, blk.f39w, blk.f38h);
            } else {
                blk = new DataBlkFloat(blk.ulx, blk.uly, blk.f39w, blk.f38h);
            }
        }
        blk.setData(this.reconstructedComps[c].getData());
        blk.offset = (this.reconstructedComps[c].f39w * blk.uly) + blk.ulx;
        blk.scanw = this.reconstructedComps[c].f39w;
        blk.progressive = false;
        return blk;
    }

    public DataBlk getCompData(DataBlk blk, int c) {
        Object dst_data = null;
        switch (blk.getDataType()) {
            case 3:
                Object dst_data_int = (int[]) blk.getData();
                if (dst_data_int == null || dst_data_int.length < blk.f39w * blk.f38h) {
                    dst_data_int = new int[(blk.f39w * blk.f38h)];
                }
                dst_data = dst_data_int;
                break;
            case 4:
                Object dst_data_float = (float[]) blk.getData();
                if (dst_data_float == null || dst_data_float.length < blk.f39w * blk.f38h) {
                    dst_data_float = new float[(blk.f39w * blk.f38h)];
                }
                dst_data = dst_data_float;
                break;
        }
        blk = getInternCompData(blk, c);
        blk.setData(dst_data);
        blk.offset = 0;
        blk.scanw = blk.f39w;
        return blk;
    }

    private void wavelet2DReconstruction(DataBlk db, SubbandSyn sb, int c) {
        if (sb.w != 0 && sb.h != 0) {
            int i;
            Object data = db.getData();
            int ulx = sb.ulx;
            int uly = sb.uly;
            int w = sb.w;
            int h = sb.h;
            Object buf = null;
            switch (sb.getHorWFilter().getDataType()) {
                case 3:
                    int i2;
                    if (w >= h) {
                        i2 = w;
                    } else {
                        i2 = h;
                    }
                    buf = new int[i2];
                    break;
                case 4:
                    buf = new float[(w >= h ? w : h)];
                    break;
            }
            int offset = (((uly - db.uly) * db.f39w) + ulx) - db.ulx;
            if (sb.ulcx % 2 == 0) {
                i = 0;
                while (i < h) {
                    System.arraycopy(data, offset, buf, 0, w);
                    sb.hFilter.synthetize_lpf(buf, 0, (w + 1) / 2, 1, buf, (w + 1) / 2, w / 2, 1, data, offset, 1);
                    i++;
                    offset += db.f39w;
                }
            } else {
                i = 0;
                while (i < h) {
                    System.arraycopy(data, offset, buf, 0, w);
                    sb.hFilter.synthetize_hpf(buf, 0, w / 2, 1, buf, w / 2, (w + 1) / 2, 1, data, offset, 1);
                    i++;
                    offset += db.f39w;
                }
            }
            offset = (((uly - db.uly) * db.f39w) + ulx) - db.ulx;
            int j;
            int k;
            switch (sb.getVerWFilter().getDataType()) {
                case 3:
                    int[] data_int = (int[]) data;
                    int[] buf_int = (int[]) buf;
                    if (sb.ulcy % 2 == 0) {
                        j = 0;
                        while (j < w) {
                            i = h - 1;
                            k = offset + (db.f39w * i);
                            while (i >= 0) {
                                buf_int[i] = data_int[k];
                                i--;
                                k -= db.f39w;
                            }
                            sb.vFilter.synthetize_lpf(buf, 0, (h + 1) / 2, 1, buf, (h + 1) / 2, h / 2, 1, data, offset, db.f39w);
                            j++;
                            offset++;
                        }
                        return;
                    }
                    j = 0;
                    while (j < w) {
                        i = h - 1;
                        k = offset + (db.f39w * i);
                        while (i >= 0) {
                            buf_int[i] = data_int[k];
                            i--;
                            k -= db.f39w;
                        }
                        sb.vFilter.synthetize_hpf(buf, 0, h / 2, 1, buf, h / 2, (h + 1) / 2, 1, data, offset, db.f39w);
                        j++;
                        offset++;
                    }
                    return;
                case 4:
                    float[] data_float = (float[]) data;
                    float[] buf_float = (float[]) buf;
                    if (sb.ulcy % 2 == 0) {
                        j = 0;
                        while (j < w) {
                            i = h - 1;
                            k = offset + (db.f39w * i);
                            while (i >= 0) {
                                buf_float[i] = data_float[k];
                                i--;
                                k -= db.f39w;
                            }
                            sb.vFilter.synthetize_lpf(buf, 0, (h + 1) / 2, 1, buf, (h + 1) / 2, h / 2, 1, data, offset, db.f39w);
                            j++;
                            offset++;
                        }
                        return;
                    }
                    j = 0;
                    while (j < w) {
                        i = h - 1;
                        k = offset + (db.f39w * i);
                        while (i >= 0) {
                            buf_float[i] = data_float[k];
                            i--;
                            k -= db.f39w;
                        }
                        sb.vFilter.synthetize_hpf(buf, 0, h / 2, 1, buf, h / 2, (h + 1) / 2, 1, data, offset, db.f39w);
                        j++;
                        offset++;
                    }
                    return;
                default:
                    return;
            }
        }
    }

    private void waveletTreeReconstruction(DataBlk img, SubbandSyn sb, int c) {
        if (sb.isNode) {
            if (sb.isNode) {
                waveletTreeReconstruction(img, (SubbandSyn) sb.getLL(), c);
                if (sb.resLvl <= (this.reslvl - this.maxImgRes) + this.ndl[c]) {
                    waveletTreeReconstruction(img, (SubbandSyn) sb.getHL(), c);
                    waveletTreeReconstruction(img, (SubbandSyn) sb.getLH(), c);
                    waveletTreeReconstruction(img, (SubbandSyn) sb.getHH(), c);
                    wavelet2DReconstruction(img, sb, c);
                }
            }
        } else if (sb.w != 0 && sb.h != 0) {
            DataBlk subbData;
            if (this.dtype == 3) {
                subbData = new DataBlkInt();
            } else {
                subbData = new DataBlkFloat();
            }
            Coord ncblks = sb.numCb;
            Object dst_data = img.getData();
            for (int m = 0; m < ncblks.f37y; m++) {
                for (int n = 0; n < ncblks.f36x; n++) {
                    subbData = this.src.getInternCodeBlock(c, m, n, sb, subbData);
                    Object src_data = subbData.getData();
                    if (this.pw != null) {
                        this.nDecCblk++;
                        this.pw.updateProgressWatch(this.nDecCblk, null);
                    }
                    for (int i = subbData.f38h - 1; i >= 0; i--) {
                        System.arraycopy(src_data, subbData.offset + (subbData.scanw * i), dst_data, ((subbData.uly + i) * img.f39w) + subbData.ulx, subbData.f39w);
                    }
                }
            }
        }
    }

    public int getImplementationType(int c) {
        return 2;
    }

    public void setTile(int x, int y) {
        int c;
        super.setTile(x, y);
        int nc = this.src.getNumComps();
        int tIdx = this.src.getTileIdx();
        for (c = 0; c < nc; c++) {
            this.ndl[c] = this.src.getSynSubbandTree(tIdx, c).resLvl;
        }
        if (this.reconstructedComps != null) {
            for (int i = this.reconstructedComps.length - 1; i >= 0; i--) {
                this.reconstructedComps[i] = null;
            }
        }
        this.cblkToDecode = 0;
        for (c = 0; c < nc; c++) {
            SubbandSyn root = this.src.getSynSubbandTree(tIdx, c);
            for (int r = 0; r <= (this.reslvl - this.maxImgRes) + root.resLvl; r++) {
                SubbandSyn sb;
                if (r == 0) {
                    sb = (SubbandSyn) root.getSubbandByIdx(0, 0);
                    if (sb != null) {
                        this.cblkToDecode += sb.numCb.f36x * sb.numCb.f37y;
                    }
                } else {
                    sb = (SubbandSyn) root.getSubbandByIdx(r, 1);
                    if (sb != null) {
                        this.cblkToDecode += sb.numCb.f36x * sb.numCb.f37y;
                    }
                    sb = (SubbandSyn) root.getSubbandByIdx(r, 2);
                    if (sb != null) {
                        this.cblkToDecode += sb.numCb.f36x * sb.numCb.f37y;
                    }
                    sb = (SubbandSyn) root.getSubbandByIdx(r, 3);
                    if (sb != null) {
                        this.cblkToDecode += sb.numCb.f36x * sb.numCb.f37y;
                    }
                }
            }
        }
        this.nDecCblk = 0;
        if (this.pw != null) {
            this.pw.initProgressWatch(0, this.cblkToDecode, "Decoding tile " + tIdx + "...");
        }
    }

    public void nextTile() {
        super.nextTile();
        int nc = this.src.getNumComps();
        int tIdx = this.src.getTileIdx();
        for (int c = 0; c < nc; c++) {
            this.ndl[c] = this.src.getSynSubbandTree(tIdx, c).resLvl;
        }
        if (this.reconstructedComps != null) {
            for (int i = this.reconstructedComps.length - 1; i >= 0; i--) {
                this.reconstructedComps[i] = null;
            }
        }
    }
}
