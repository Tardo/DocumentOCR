package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.ModuleSpec;

public class SynWTFilterSpec extends ModuleSpec {
    public SynWTFilterSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public int getWTDataType(int t, int c) {
        return ((SynWTFilter[][]) getSpec(t, c))[0][0].getDataType();
    }

    public SynWTFilter[] getHFilters(int t, int c) {
        return ((SynWTFilter[][]) getSpec(t, c))[0];
    }

    public SynWTFilter[] getVFilters(int t, int c) {
        return ((SynWTFilter[][]) getSpec(t, c))[1];
    }

    public String toString() {
        String str = "" + "nTiles=" + this.nTiles + "\nnComp=" + this.nComp + "\n\n";
        for (int t = 0; t < this.nTiles; t++) {
            for (int c = 0; c < this.nComp; c++) {
                SynWTFilter[][] an = (SynWTFilter[][]) getSpec(t, c);
                str = (str + "(t:" + t + ",c:" + c + ")\n") + "\tH:";
                for (Object obj : an[0]) {
                    str = str + " " + obj;
                }
                str = str + "\n\tV:";
                for (Object obj2 : an[1]) {
                    str = str + " " + obj2;
                }
                str = str + "\n";
            }
        }
        return str;
    }

    public boolean isReversible(int t, int c) {
        SynWTFilter[] hfilter = getHFilters(t, c);
        SynWTFilter[] vfilter = getVFilters(t, c);
        int i = hfilter.length - 1;
        while (i >= 0) {
            if (!hfilter[i].isReversible() || !vfilter[i].isReversible()) {
                return false;
            }
            i--;
        }
        return true;
    }
}
