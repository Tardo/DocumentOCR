package jj2000.j2k.codestream;

public abstract class CoordInfo {
    /* renamed from: h */
    public int f21h;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f22w;

    public CoordInfo(int ulx, int uly, int w, int h) {
        this.ulx = ulx;
        this.uly = uly;
        this.f22w = w;
        this.f21h = h;
    }

    public String toString() {
        return "ulx=" + this.ulx + ",uly=" + this.uly + ",w=" + this.f22w + ",h=" + this.f21h;
    }
}
