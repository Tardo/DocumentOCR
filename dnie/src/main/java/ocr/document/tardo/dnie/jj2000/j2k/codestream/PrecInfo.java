package jj2000.j2k.codestream;

public class PrecInfo {
    public CBlkCoordInfo[][][] cblk;
    /* renamed from: h */
    public int f23h;
    public int[] nblk;
    /* renamed from: r */
    public int f24r;
    public int rgh;
    public int rgulx;
    public int rguly;
    public int rgw;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f25w;

    public PrecInfo(int r, int ulx, int uly, int w, int h, int rgulx, int rguly, int rgw, int rgh) {
        this.f24r = r;
        this.ulx = ulx;
        this.uly = uly;
        this.f25w = w;
        this.f23h = h;
        this.rgulx = rgulx;
        this.rguly = rguly;
        this.rgw = rgw;
        this.rgh = rgh;
        if (r == 0) {
            this.cblk = new CBlkCoordInfo[1][][];
            this.nblk = new int[1];
            return;
        }
        this.cblk = new CBlkCoordInfo[4][][];
        this.nblk = new int[4];
    }

    public String toString() {
        return "ulx=" + this.ulx + ",uly=" + this.uly + ",w=" + this.f25w + ",h=" + this.f23h + ",rgulx=" + this.rgulx + ",rguly=" + this.rguly + ",rgw=" + this.rgw + ",rgh=" + this.rgh;
    }
}
