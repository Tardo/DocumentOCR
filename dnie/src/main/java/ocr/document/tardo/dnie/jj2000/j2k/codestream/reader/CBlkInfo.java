package jj2000.j2k.codestream.reader;

public class CBlkInfo {
    public int ctp;
    /* renamed from: h */
    public int f26h;
    public int[] len;
    public int msbSkipped;
    public int[] ntp;
    public int[] off;
    public int[] pktIdx;
    public int[][] segLen;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f27w;

    public CBlkInfo(int ulx, int uly, int w, int h, int nl) {
        this.ulx = ulx;
        this.uly = uly;
        this.f27w = w;
        this.f26h = h;
        this.off = new int[nl];
        this.len = new int[nl];
        this.ntp = new int[nl];
        this.segLen = new int[nl][];
        this.pktIdx = new int[nl];
        for (int i = nl - 1; i >= 0; i--) {
            this.pktIdx[i] = -1;
        }
    }

    public void addNTP(int l, int newtp) {
        this.ntp[l] = newtp;
        this.ctp = 0;
        for (int lIdx = 0; lIdx <= l; lIdx++) {
            this.ctp += this.ntp[lIdx];
        }
    }

    public String toString() {
        String string = ("(ulx,uly,w,h)= (" + this.ulx + "," + this.uly + "," + this.f27w + "," + this.f26h) + ") " + this.msbSkipped + " MSB bit(s) skipped\n";
        if (this.len != null) {
            int i = 0;
            while (i < this.len.length) {
                string = string + "\tl:" + i + ", start:" + this.off[i] + ", len:" + this.len[i] + ", ntp:" + this.ntp[i] + ", pktIdx=" + this.pktIdx[i];
                if (!(this.segLen == null || this.segLen[i] == null)) {
                    string = string + " { ";
                    for (int i2 : this.segLen[i]) {
                        string = string + i2 + " ";
                    }
                    string = string + "}";
                }
                string = string + "\n";
                i++;
            }
        }
        return string + "\tctp=" + this.ctp;
    }
}
