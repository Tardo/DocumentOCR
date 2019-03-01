package colorspace;

import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.FacilityManager;

public class SYccColorSpaceMapper extends ColorSpaceMapper {
    protected static float Matrix00 = 1.0f;
    protected static float Matrix01 = 0.0f;
    protected static float Matrix02 = 1.402f;
    protected static float Matrix10 = 1.0f;
    protected static float Matrix11 = -0.34413f;
    protected static float Matrix12 = -0.71414f;
    protected static float Matrix20 = 1.0f;
    protected static float Matrix21 = 1.772f;
    protected static float Matrix22 = 0.0f;

    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        return new SYccColorSpaceMapper(src, csMap);
    }

    protected SYccColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src, csMap);
        initialize();
    }

    private void initialize() throws ColorSpaceException {
        if (this.ncomps != 1 && this.ncomps != 3) {
            String msg = "SYccColorSpaceMapper: ycc transformation _not_ applied to " + this.ncomps + " component image";
            FacilityManager.getMsgLogger().printmsg(3, msg);
            throw new ColorSpaceException(msg);
        }
    }

    public DataBlk getCompData(DataBlk outblk, int c) {
        int type = outblk.getDataType();
        for (int i = 0; i < this.ncomps; i++) {
            ColorSpaceMapper.copyGeometry(this.workInt[i], outblk);
            ColorSpaceMapper.copyGeometry(this.workFloat[i], outblk);
            ColorSpaceMapper.copyGeometry(this.inInt[i], outblk);
            ColorSpaceMapper.copyGeometry(this.inFloat[i], outblk);
            this.inInt[i] = (DataBlkInt) this.src.getInternCompData(this.inInt[i], i);
        }
        if (type == 3) {
            if (this.ncomps == 1) {
                this.workInt[c] = this.inInt[c];
            } else {
                this.workInt = mult(this.inInt);
            }
            outblk.progressive = this.inInt[c].progressive;
            outblk.setData(this.workInt[c].getData());
        }
        if (type == 4) {
            if (this.ncomps == 1) {
                this.workFloat[c] = this.inFloat[c];
            } else {
                this.workFloat = mult(this.inFloat);
            }
            outblk.progressive = this.inFloat[c].progressive;
            outblk.setData(this.workFloat[c].getData());
        }
        outblk.offset = 0;
        outblk.scanw = outblk.f39w;
        return outblk;
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return getCompData(out, c);
    }

    private static DataBlkFloat[] mult(DataBlkFloat[] inblk) {
        if (inblk.length != 3) {
            throw new IllegalArgumentException("bad input array size");
        }
        int length = inblk[0].h * inblk[0].w;
        DataBlkFloat[] outblk = new DataBlkFloat[3];
        float[][] out = new float[3][];
        float[][] in = new float[3][];
        for (int i = 0; i < 3; i++) {
            in[i] = inblk[i].getDataFloat();
            outblk[i] = new DataBlkFloat();
            ColorSpaceMapper.copyGeometry(outblk[i], inblk[i]);
            outblk[i].offset = inblk[i].offset;
            out[i] = new float[length];
            outblk[i].setData(out[i]);
        }
        for (int j = 0; j < length; j++) {
            out[0][j] = ((Matrix00 * in[0][inblk[0].offset + j]) + (Matrix01 * in[1][inblk[1].offset + j])) + (Matrix02 * in[2][inblk[2].offset + j]);
            out[1][j] = ((Matrix10 * in[0][inblk[0].offset + j]) + (Matrix11 * in[1][inblk[1].offset + j])) + (Matrix12 * in[2][inblk[2].offset + j]);
            out[2][j] = ((Matrix20 * in[0][inblk[0].offset + j]) + (Matrix21 * in[1][inblk[1].offset + j])) + (Matrix22 * in[2][inblk[2].offset + j]);
        }
        return outblk;
    }

    private static DataBlkInt[] mult(DataBlkInt[] inblk) {
        if (inblk.length != 3) {
            throw new IllegalArgumentException("bad input array size");
        }
        int length = inblk[0].h * inblk[0].w;
        DataBlkInt[] outblk = new DataBlkInt[3];
        int[][] out = new int[3][];
        int[][] in = new int[3][];
        for (int i = 0; i < 3; i++) {
            in[i] = inblk[i].getDataInt();
            outblk[i] = new DataBlkInt();
            ColorSpaceMapper.copyGeometry(outblk[i], inblk[i]);
            outblk[i].offset = inblk[i].offset;
            out[i] = new int[length];
            outblk[i].setData(out[i]);
        }
        for (int j = 0; j < length; j++) {
            out[0][j] = (int) (((Matrix00 * ((float) in[0][inblk[0].offset + j])) + (Matrix01 * ((float) in[1][inblk[1].offset + j]))) + (Matrix02 * ((float) in[2][inblk[2].offset + j])));
            out[1][j] = (int) (((Matrix10 * ((float) in[0][inblk[0].offset + j])) + (Matrix11 * ((float) in[1][inblk[1].offset + j]))) + (Matrix12 * ((float) in[2][inblk[2].offset + j])));
            out[2][j] = (int) (((Matrix20 * ((float) in[0][inblk[0].offset + j])) + (Matrix21 * ((float) in[1][inblk[1].offset + j]))) + (Matrix22 * ((float) in[2][inblk[2].offset + j])));
        }
        return outblk;
    }

    public String toString() {
        StringBuffer rep_nComps = new StringBuffer("ncomps= ").append(String.valueOf(this.ncomps));
        StringBuffer rep_comps = new StringBuffer();
        for (int i = 0; i < this.ncomps; i++) {
            rep_comps.append("  ").append("component[").append(String.valueOf(i)).append("] height, width = (").append(this.src.getCompImgHeight(i)).append(", ").append(this.src.getCompImgWidth(i)).append(")").append(eol);
        }
        StringBuffer rep = new StringBuffer("[SYccColorSpaceMapper ");
        rep.append(rep_nComps).append(eol);
        rep.append(rep_comps).append("  ");
        return rep.append("]").toString();
    }
}
