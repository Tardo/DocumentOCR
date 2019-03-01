package jj2000.j2k.entropy.decoder;

import jj2000.j2k.entropy.CodedCBlk;

public class DecLyrdCBlk extends CodedCBlk {
    public int dl;
    public int ftpIdx;
    /* renamed from: h */
    public int f215h;
    public int nTrunc;
    public int nl;
    public boolean prog;
    public int[] tsLengths;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f216w;

    public String toString() {
        String str = "Coded code-block (" + this.m + "," + this.n + "): " + this.skipMSBP + " MSB skipped, " + this.dl + " bytes, " + this.nTrunc + " truncation points, " + this.nl + " layers, " + "progressive=" + this.prog + ", ulx=" + this.ulx + ", uly=" + this.uly + ", w=" + this.f216w + ", h=" + this.f215h + ", ftpIdx=" + this.ftpIdx;
        if (this.tsLengths == null) {
            return str;
        }
        str = str + " {";
        for (int i : this.tsLengths) {
            str = str + " " + i;
        }
        return str + " }";
    }
}
