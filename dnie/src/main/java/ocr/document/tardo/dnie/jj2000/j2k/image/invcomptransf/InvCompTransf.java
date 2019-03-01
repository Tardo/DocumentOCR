package jj2000.j2k.image.invcomptransf;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.CompTransfSpec;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.image.ImgDataAdapter;
import jj2000.j2k.util.MathUtil;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.SynWTFilterSpec;

public class InvCompTransf extends ImgDataAdapter implements BlkImgDataSrc {
    public static final int INV_ICT = 2;
    public static final int INV_RCT = 1;
    public static final int NONE = 0;
    public static final char OPT_PREFIX = 'M';
    private static final String[][] pinfo = ((String[][]) null);
    private DataBlk block0;
    private DataBlk block1;
    private DataBlk block2;
    private CompTransfSpec cts;
    private DataBlkInt dbi = new DataBlkInt();
    private boolean noCompTransf = false;
    private int[][] outdata = new int[3][];
    private BlkImgDataSrc src;
    private int transfType = 0;
    private int[] utdepth;
    private SynWTFilterSpec wfs;

    public InvCompTransf(BlkImgDataSrc imgSrc, DecoderSpecs decSpec, int[] utdepth, ParameterList pl) {
        boolean z = false;
        super(imgSrc);
        this.cts = decSpec.cts;
        this.wfs = decSpec.wfs;
        this.src = imgSrc;
        this.utdepth = utdepth;
        if (!pl.getBooleanParameter("comp_transf")) {
            z = true;
        }
        this.noCompTransf = z;
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    public String toString() {
        switch (this.transfType) {
            case 0:
                return "No component transformation";
            case 1:
                return "Inverse RCT";
            case 2:
                return "Inverse ICT";
            default:
                throw new IllegalArgumentException("Non JPEG 2000 part I component transformation");
        }
    }

    public boolean isReversible() {
        switch (this.transfType) {
            case 0:
            case 1:
                return true;
            case 2:
                return false;
            default:
                throw new IllegalArgumentException("Non JPEG 2000 part I component transformation");
        }
    }

    public int getFixedPoint(int c) {
        return this.src.getFixedPoint(c);
    }

    public static int[] calcMixedBitDepths(int[] utdepth, int ttype, int[] tdepth) {
        if (utdepth.length >= 3 || ttype == 0) {
            if (tdepth == null) {
                tdepth = new int[utdepth.length];
            }
            switch (ttype) {
                case 0:
                    System.arraycopy(utdepth, 0, tdepth, 0, utdepth.length);
                    break;
                case 1:
                    if (utdepth.length > 3) {
                        System.arraycopy(utdepth, 3, tdepth, 3, utdepth.length - 3);
                    }
                    tdepth[0] = (MathUtil.log2((((1 << utdepth[0]) + (2 << utdepth[1])) + (1 << utdepth[2])) - 1) - 2) + 1;
                    tdepth[1] = MathUtil.log2(((1 << utdepth[2]) + (1 << utdepth[1])) - 1) + 1;
                    tdepth[2] = MathUtil.log2(((1 << utdepth[0]) + (1 << utdepth[1])) - 1) + 1;
                    break;
                case 2:
                    if (utdepth.length > 3) {
                        System.arraycopy(utdepth, 3, tdepth, 3, utdepth.length - 3);
                    }
                    tdepth[0] = MathUtil.log2(((int) Math.floor(((((double) (1 << utdepth[0])) * 0.299072d) + (((double) (1 << utdepth[1])) * 0.586914d)) + (((double) (1 << utdepth[2])) * 0.114014d))) - 1) + 1;
                    tdepth[1] = MathUtil.log2(((int) Math.floor(((((double) (1 << utdepth[0])) * 0.168701d) + (((double) (1 << utdepth[1])) * 0.331299d)) + (((double) (1 << utdepth[2])) * 0.5d))) - 1) + 1;
                    tdepth[2] = MathUtil.log2(((int) Math.floor(((((double) (1 << utdepth[0])) * 0.5d) + (((double) (1 << utdepth[1])) * 0.418701d)) + (((double) (1 << utdepth[2])) * 0.081299d))) - 1) + 1;
                    break;
            }
            return tdepth;
        }
        throw new IllegalArgumentException();
    }

    public int getNomRangeBits(int c) {
        return this.utdepth[c];
    }

    public DataBlk getCompData(DataBlk blk, int c) {
        if (c >= 3 || this.transfType == 0 || this.noCompTransf) {
            return this.src.getCompData(blk, c);
        }
        return getInternCompData(blk, c);
    }

    public DataBlk getInternCompData(DataBlk blk, int c) {
        if (this.noCompTransf) {
            return this.src.getInternCompData(blk, c);
        }
        switch (this.transfType) {
            case 0:
                return this.src.getInternCompData(blk, c);
            case 1:
                return invRCT(blk, c);
            case 2:
                return invICT(blk, c);
            default:
                throw new IllegalArgumentException("Non JPEG 2000 part I component transformation");
        }
    }

    private DataBlk invRCT(DataBlk blk, int c) {
        if (c >= 3 && c < getNumComps()) {
            return this.src.getInternCompData(blk, c);
        }
        if (this.outdata[c] == null || this.dbi.ulx > blk.ulx || this.dbi.uly > blk.uly || this.dbi.ulx + this.dbi.w < blk.ulx + blk.f39w || this.dbi.uly + this.dbi.h < blk.uly + blk.f38h) {
            int w = blk.f39w;
            int h = blk.f38h;
            this.outdata[c] = (int[]) blk.getData();
            if (this.outdata[c] == null || this.outdata[c].length != h * w) {
                this.outdata[c] = new int[(h * w)];
                blk.setData(this.outdata[c]);
            }
            this.outdata[(c + 1) % 3] = new int[this.outdata[c].length];
            this.outdata[(c + 2) % 3] = new int[this.outdata[c].length];
            if (this.block0 == null || this.block0.getDataType() != 3) {
                this.block0 = new DataBlkInt();
            }
            if (this.block1 == null || this.block1.getDataType() != 3) {
                this.block1 = new DataBlkInt();
            }
            if (this.block2 == null || this.block2.getDataType() != 3) {
                this.block2 = new DataBlkInt();
            }
            DataBlk dataBlk = this.block0;
            DataBlk dataBlk2 = this.block1;
            DataBlk dataBlk3 = this.block2;
            int i = blk.f39w;
            dataBlk3.f39w = i;
            dataBlk2.f39w = i;
            dataBlk.f39w = i;
            dataBlk = this.block0;
            dataBlk2 = this.block1;
            dataBlk3 = this.block2;
            i = blk.f38h;
            dataBlk3.f38h = i;
            dataBlk2.f38h = i;
            dataBlk.f38h = i;
            dataBlk = this.block0;
            dataBlk2 = this.block1;
            dataBlk3 = this.block2;
            i = blk.ulx;
            dataBlk3.ulx = i;
            dataBlk2.ulx = i;
            dataBlk.ulx = i;
            dataBlk = this.block0;
            dataBlk2 = this.block1;
            dataBlk3 = this.block2;
            i = blk.uly;
            dataBlk3.uly = i;
            dataBlk2.uly = i;
            dataBlk.uly = i;
            this.block0 = (DataBlkInt) this.src.getInternCompData(this.block0, 0);
            int[] data0 = (int[]) this.block0.getData();
            this.block1 = (DataBlkInt) this.src.getInternCompData(this.block1, 1);
            int[] data1 = (int[]) this.block1.getData();
            this.block2 = (DataBlkInt) this.src.getInternCompData(this.block2, 2);
            int[] data2 = (int[]) this.block2.getData();
            boolean z = this.block0.progressive || this.block1.progressive || this.block2.progressive;
            blk.progressive = z;
            blk.offset = 0;
            blk.scanw = w;
            this.dbi.progressive = blk.progressive;
            this.dbi.ulx = blk.ulx;
            this.dbi.uly = blk.uly;
            this.dbi.w = blk.f39w;
            this.dbi.h = blk.f38h;
            int k = (w * h) - 1;
            int k0 = ((this.block0.offset + ((h - 1) * this.block0.scanw)) + w) - 1;
            int k1 = ((this.block1.offset + ((h - 1) * this.block1.scanw)) + w) - 1;
            int k2 = ((this.block2.offset + ((h - 1) * this.block2.scanw)) + w) - 1;
            for (int i2 = h - 1; i2 >= 0; i2--) {
                int mink = k - w;
                while (k > mink) {
                    this.outdata[1][k] = data0[k0] - ((data1[k1] + data2[k2]) >> 2);
                    this.outdata[0][k] = data2[k2] + this.outdata[1][k];
                    this.outdata[2][k] = data1[k1] + this.outdata[1][k];
                    k--;
                    k0--;
                    k1--;
                    k2--;
                }
                k0 -= this.block0.scanw - w;
                k1 -= this.block1.scanw - w;
                k2 -= this.block2.scanw - w;
            }
            this.outdata[c] = null;
            return blk;
        } else if (c < 0 || c >= 3) {
            throw new IllegalArgumentException();
        } else {
            blk.setData(this.outdata[c]);
            blk.progressive = this.dbi.progressive;
            blk.offset = (((blk.uly - this.dbi.uly) * this.dbi.w) + blk.ulx) - this.dbi.ulx;
            blk.scanw = this.dbi.w;
            this.outdata[c] = null;
            return blk;
        }
    }

    private DataBlk invICT(DataBlk blk, int c) {
        int w;
        int h;
        int k;
        int k0;
        int i;
        int mink;
        if (c >= 3 && c < getNumComps()) {
            w = blk.f39w;
            h = blk.f38h;
            int[] outdata = (int[]) blk.getData();
            if (outdata == null) {
                outdata = new int[(h * w)];
                blk.setData(outdata);
            }
            DataBlkFloat indb = new DataBlkFloat(blk.ulx, blk.uly, w, h);
            this.src.getInternCompData(indb, c);
            float[] indata = (float[]) indb.getData();
            k = (w * h) - 1;
            k0 = ((indb.offset + ((h - 1) * indb.scanw)) + w) - 1;
            for (i = h - 1; i >= 0; i--) {
                mink = k - w;
                while (k > mink) {
                    outdata[k] = (int) indata[k0];
                    k--;
                    k0--;
                }
                k0 -= indb.scanw - w;
            }
            blk.progressive = indb.progressive;
            blk.offset = 0;
            blk.scanw = w;
        } else if (this.outdata[c] == null || this.dbi.ulx > blk.ulx || this.dbi.uly > blk.uly || this.dbi.ulx + this.dbi.w < blk.ulx + blk.f39w || this.dbi.uly + this.dbi.h < blk.uly + blk.f38h) {
            w = blk.f39w;
            h = blk.f38h;
            this.outdata[c] = (int[]) blk.getData();
            if (this.outdata[c] == null || this.outdata[c].length != w * h) {
                this.outdata[c] = new int[(h * w)];
                blk.setData(this.outdata[c]);
            }
            this.outdata[(c + 1) % 3] = new int[this.outdata[c].length];
            this.outdata[(c + 2) % 3] = new int[this.outdata[c].length];
            if (this.block0 == null || this.block0.getDataType() != 4) {
                this.block0 = new DataBlkFloat();
            }
            if (this.block2 == null || this.block2.getDataType() != 4) {
                this.block2 = new DataBlkFloat();
            }
            if (this.block1 == null || this.block1.getDataType() != 4) {
                this.block1 = new DataBlkFloat();
            }
            DataBlk dataBlk = this.block0;
            DataBlk dataBlk2 = this.block2;
            DataBlk dataBlk3 = this.block1;
            int i2 = blk.f39w;
            dataBlk3.f39w = i2;
            dataBlk2.f39w = i2;
            dataBlk.f39w = i2;
            dataBlk = this.block0;
            dataBlk2 = this.block2;
            dataBlk3 = this.block1;
            i2 = blk.f38h;
            dataBlk3.f38h = i2;
            dataBlk2.f38h = i2;
            dataBlk.f38h = i2;
            dataBlk = this.block0;
            dataBlk2 = this.block2;
            dataBlk3 = this.block1;
            i2 = blk.ulx;
            dataBlk3.ulx = i2;
            dataBlk2.ulx = i2;
            dataBlk.ulx = i2;
            dataBlk = this.block0;
            dataBlk2 = this.block2;
            dataBlk3 = this.block1;
            i2 = blk.uly;
            dataBlk3.uly = i2;
            dataBlk2.uly = i2;
            dataBlk.uly = i2;
            this.block0 = (DataBlkFloat) this.src.getInternCompData(this.block0, 0);
            float[] data0 = (float[]) this.block0.getData();
            this.block2 = (DataBlkFloat) this.src.getInternCompData(this.block2, 1);
            float[] data2 = (float[]) this.block2.getData();
            this.block1 = (DataBlkFloat) this.src.getInternCompData(this.block1, 2);
            float[] data1 = (float[]) this.block1.getData();
            boolean z = this.block0.progressive || this.block1.progressive || this.block2.progressive;
            blk.progressive = z;
            blk.offset = 0;
            blk.scanw = w;
            this.dbi.progressive = blk.progressive;
            this.dbi.ulx = blk.ulx;
            this.dbi.uly = blk.uly;
            this.dbi.w = blk.f39w;
            this.dbi.h = blk.f38h;
            k = (w * h) - 1;
            k0 = ((this.block0.offset + ((h - 1) * this.block0.scanw)) + w) - 1;
            int k2 = ((this.block2.offset + ((h - 1) * this.block2.scanw)) + w) - 1;
            int k1 = ((this.block1.offset + ((h - 1) * this.block1.scanw)) + w) - 1;
            for (i = h - 1; i >= 0; i--) {
                mink = k - w;
                while (k > mink) {
                    this.outdata[0][k] = (int) ((data0[k0] + (1.402f * data1[k1])) + 0.5f);
                    this.outdata[1][k] = (int) (((data0[k0] - (0.34413f * data2[k2])) - (0.71414f * data1[k1])) + 0.5f);
                    this.outdata[2][k] = (int) ((data0[k0] + (1.772f * data2[k2])) + 0.5f);
                    k--;
                    k0--;
                    k2--;
                    k1--;
                }
                k0 -= this.block0.scanw - w;
                k2 -= this.block2.scanw - w;
                k1 -= this.block1.scanw - w;
            }
            this.outdata[c] = null;
        } else if (c < 0 || c > 3) {
            throw new IllegalArgumentException();
        } else {
            blk.setData(this.outdata[c]);
            blk.progressive = this.dbi.progressive;
            blk.offset = (((blk.uly - this.dbi.uly) * this.dbi.w) + blk.ulx) - this.dbi.ulx;
            blk.scanw = this.dbi.w;
            this.outdata[c] = null;
        }
        return blk;
    }

    public void setTile(int x, int y) {
        this.src.setTile(x, y);
        this.tIdx = getTileIdx();
        if (((Integer) this.cts.getTileDef(this.tIdx)).intValue() == 0) {
            this.transfType = 0;
            return;
        }
        int nc = this.src.getNumComps() > 3 ? 3 : this.src.getNumComps();
        int rev = 0;
        for (int c = 0; c < nc; c++) {
            int i;
            if (this.wfs.isReversible(this.tIdx, c)) {
                i = 1;
            } else {
                i = 0;
            }
            rev += i;
        }
        if (rev == 3) {
            this.transfType = 1;
        } else if (rev == 0) {
            this.transfType = 2;
        } else {
            throw new IllegalArgumentException("Wavelet transformation and component transformation not coherent in tile" + this.tIdx);
        }
    }

    public void nextTile() {
        this.src.nextTile();
        this.tIdx = getTileIdx();
        if (((Integer) this.cts.getTileDef(this.tIdx)).intValue() == 0) {
            this.transfType = 0;
            return;
        }
        int nc = this.src.getNumComps() > 3 ? 3 : this.src.getNumComps();
        int rev = 0;
        for (int c = 0; c < nc; c++) {
            int i;
            if (this.wfs.isReversible(this.tIdx, c)) {
                i = 1;
            } else {
                i = 0;
            }
            rev += i;
        }
        if (rev == 3) {
            this.transfType = 1;
        } else if (rev == 0) {
            this.transfType = 2;
        } else {
            throw new IllegalArgumentException("Wavelet transformation and component transformation not coherent in tile" + this.tIdx);
        }
    }
}
