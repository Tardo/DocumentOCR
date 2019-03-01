package jj2000.j2k.codestream;

public class PrecCoordInfo extends CoordInfo {
    public int xref;
    public int yref;

    public PrecCoordInfo(int ulx, int uly, int w, int h, int xref, int yref) {
        super(ulx, uly, w, h);
        this.xref = xref;
        this.yref = yref;
    }

    public String toString() {
        return super.toString() + ", xref=" + this.xref + ", yref=" + this.yref;
    }
}
