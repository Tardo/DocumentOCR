package colorspace;

import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;

public class ChannelDefinitionMapper extends ColorSpaceMapper {
    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        return new ChannelDefinitionMapper(src, csMap);
    }

    protected ChannelDefinitionMapper(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src, csMap);
    }

    public DataBlk getCompData(DataBlk out, int c) {
        return this.src.getCompData(out, this.csMap.getChannelDefinition(c));
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return this.src.getInternCompData(out, this.csMap.getChannelDefinition(c));
    }

    public int getFixedPoint(int c) {
        return this.src.getFixedPoint(this.csMap.getChannelDefinition(c));
    }

    public int getNomRangeBits(int c) {
        return this.src.getNomRangeBits(this.csMap.getChannelDefinition(c));
    }

    public int getCompImgHeight(int c) {
        return this.src.getCompImgHeight(this.csMap.getChannelDefinition(c));
    }

    public int getCompImgWidth(int c) {
        return this.src.getCompImgWidth(this.csMap.getChannelDefinition(c));
    }

    public int getCompSubsX(int c) {
        return this.src.getCompSubsX(this.csMap.getChannelDefinition(c));
    }

    public int getCompSubsY(int c) {
        return this.src.getCompSubsY(this.csMap.getChannelDefinition(c));
    }

    public int getCompULX(int c) {
        return this.src.getCompULX(this.csMap.getChannelDefinition(c));
    }

    public int getCompULY(int c) {
        return this.src.getCompULY(this.csMap.getChannelDefinition(c));
    }

    public int getTileCompHeight(int t, int c) {
        return this.src.getTileCompHeight(t, this.csMap.getChannelDefinition(c));
    }

    public int getTileCompWidth(int t, int c) {
        return this.src.getTileCompWidth(t, this.csMap.getChannelDefinition(c));
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[ChannelDefinitionMapper nchannels= ").append(this.ncomps);
        for (int i = 0; i < this.ncomps; i++) {
            rep.append(eol).append("  component[").append(i).append("] mapped to channel[").append(this.csMap.getChannelDefinition(i)).append("]");
        }
        return rep.append("]").toString();
    }
}
