package colorspace;

import colorspace.boxes.PaletteBox;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.FacilityManager;

public class PalettizedColorSpaceMapper extends ColorSpaceMapper {
    int[] outShiftValueArray;
    private PaletteBox pbox;
    int srcChannel = 0;

    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        return new PalettizedColorSpaceMapper(src, csMap);
    }

    protected PalettizedColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src, csMap);
        this.pbox = csMap.getPaletteBox();
        initialize();
    }

    private void initialize() throws ColorSpaceException {
        if (this.ncomps == 1 || this.ncomps == 3) {
            int outComps = getNumComps();
            this.outShiftValueArray = new int[outComps];
            for (int i = 0; i < outComps; i++) {
                this.outShiftValueArray[i] = 1 << (getNomRangeBits(i) - 1);
            }
            return;
        }
        throw new ColorSpaceException("wrong number of components (" + this.ncomps + ") for palettized image");
    }

    public DataBlk getCompData(DataBlk out, int c) {
        if (this.pbox == null) {
            return this.src.getCompData(out, c);
        }
        if (this.ncomps != 1) {
            FacilityManager.getMsgLogger().printmsg(2, "PalettizedColorSpaceMapper: color palette _not_ applied, incorrect number (" + String.valueOf(this.ncomps) + ") of components");
            return this.src.getCompData(out, c);
        }
        ColorSpaceMapper.setInternalBuffer(out);
        int row;
        int leftedgeIn;
        int rightedgeIn;
        int leftedgeOut;
        int rightedgeOut;
        int kOut;
        int kIn;
        switch (out.getDataType()) {
            case 3:
                ColorSpaceMapper.copyGeometry(this.inInt[0], out);
                this.inInt[0] = (DataBlkInt) this.src.getInternCompData(this.inInt[0], 0);
                this.dataInt[0] = (int[]) this.inInt[0].getData();
                int[] outdataInt = ((DataBlkInt) out).getDataInt();
                for (row = 0; row < out.f38h; row++) {
                    leftedgeIn = this.inInt[0].offset + (this.inInt[0].scanw * row);
                    rightedgeIn = leftedgeIn + this.inInt[0].w;
                    leftedgeOut = out.offset + (out.scanw * row);
                    rightedgeOut = leftedgeOut + out.f39w;
                    kOut = leftedgeOut;
                    kIn = leftedgeIn;
                    while (kIn < rightedgeIn) {
                        outdataInt[kOut] = this.pbox.getEntry(c, this.dataInt[0][kIn] + this.shiftValueArray[0]) - this.outShiftValueArray[c];
                        kIn++;
                        kOut++;
                    }
                }
                out.progressive = this.inInt[0].progressive;
                break;
            case 4:
                ColorSpaceMapper.copyGeometry(this.inFloat[0], out);
                this.inFloat[0] = (DataBlkFloat) this.src.getInternCompData(this.inFloat[0], 0);
                this.dataFloat[0] = (float[]) this.inFloat[0].getData();
                float[] outdataFloat = ((DataBlkFloat) out).getDataFloat();
                for (row = 0; row < out.f38h; row++) {
                    leftedgeIn = this.inFloat[0].offset + (this.inFloat[0].scanw * row);
                    rightedgeIn = leftedgeIn + this.inFloat[0].w;
                    leftedgeOut = out.offset + (out.scanw * row);
                    rightedgeOut = leftedgeOut + out.f39w;
                    kOut = leftedgeOut;
                    kIn = leftedgeIn;
                    while (kIn < rightedgeIn) {
                        outdataFloat[kOut] = (float) (this.pbox.getEntry(c, ((int) this.dataFloat[0][kIn]) + this.shiftValueArray[0]) - this.outShiftValueArray[c]);
                        kIn++;
                        kOut++;
                    }
                }
                out.progressive = this.inFloat[0].progressive;
                break;
            default:
                throw new IllegalArgumentException("invalid source datablock type");
        }
        out.offset = 0;
        out.scanw = out.f39w;
        return out;
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[PalettizedColorSpaceMapper ");
        StringBuffer body = new StringBuffer("  " + eol);
        if (this.pbox != null) {
            body.append("ncomps= ").append(getNumComps()).append(", scomp= ").append(this.srcChannel);
            for (int c = 0; c < getNumComps(); c++) {
                body.append(eol).append("column= ").append(c).append(", ").append(this.pbox.getBitDepth(c)).append(" bit ").append(this.pbox.isSigned(c) ? "signed entry" : "unsigned entry");
            }
        } else {
            body.append("image does not contain a palette box");
        }
        rep.append(ColorSpace.indent("  ", body));
        return rep.append("]").toString();
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return getCompData(out, c);
    }

    public int getNomRangeBits(int c) {
        return this.pbox == null ? this.src.getNomRangeBits(c) : this.pbox.getBitDepth(c);
    }

    public int getNumComps() {
        return this.pbox == null ? this.src.getNumComps() : this.pbox.getNumColumns();
    }

    public int getCompSubsX(int c) {
        return this.imgdatasrc.getCompSubsX(this.srcChannel);
    }

    public int getCompSubsY(int c) {
        return this.imgdatasrc.getCompSubsY(this.srcChannel);
    }

    public int getTileCompWidth(int t, int c) {
        return this.imgdatasrc.getTileCompWidth(t, this.srcChannel);
    }

    public int getTileCompHeight(int t, int c) {
        return this.imgdatasrc.getTileCompHeight(t, this.srcChannel);
    }

    public int getCompImgWidth(int c) {
        return this.imgdatasrc.getCompImgWidth(this.srcChannel);
    }

    public int getCompImgHeight(int c) {
        return this.imgdatasrc.getCompImgHeight(this.srcChannel);
    }

    public int getCompULX(int c) {
        return this.imgdatasrc.getCompULX(this.srcChannel);
    }

    public int getCompULY(int c) {
        return this.imgdatasrc.getCompULY(this.srcChannel);
    }
}
