package colorspace;

import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;

public class EnumeratedColorSpaceMapper extends ColorSpaceMapper {
    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        return new EnumeratedColorSpaceMapper(src, csMap);
    }

    protected EnumeratedColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src, csMap);
    }

    public DataBlk getCompData(DataBlk out, int c) {
        return this.src.getCompData(out, c);
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return this.src.getInternCompData(out, c);
    }

    public String toString() {
        StringBuffer rep_nComps = new StringBuffer("ncomps= ").append(String.valueOf(this.ncomps));
        StringBuffer rep_fixedValue = new StringBuffer("fixedPointBits= (");
        StringBuffer rep_shiftValue = new StringBuffer("shiftValue= (");
        StringBuffer rep_maxValue = new StringBuffer("maxValue= (");
        for (int i = 0; i < this.ncomps; i++) {
            if (i != 0) {
                rep_shiftValue.append(", ");
                rep_maxValue.append(", ");
                rep_fixedValue.append(", ");
            }
            rep_shiftValue.append(String.valueOf(this.shiftValueArray[i]));
            rep_maxValue.append(String.valueOf(this.maxValueArray[i]));
            rep_fixedValue.append(String.valueOf(this.fixedPtBitsArray[i]));
        }
        rep_shiftValue.append(")");
        rep_maxValue.append(")");
        rep_fixedValue.append(")");
        StringBuffer rep = new StringBuffer("[EnumeratedColorSpaceMapper ");
        rep.append(rep_nComps);
        rep.append(eol).append("  ").append(rep_shiftValue);
        rep.append(eol).append("  ").append(rep_maxValue);
        rep.append(eol).append("  ").append(rep_fixedValue);
        return rep.append("]").toString();
    }
}
