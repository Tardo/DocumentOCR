package jj2000.j2k.codestream;

import jj2000.j2k.image.Coord;

public class CBlkCoordInfo extends CoordInfo {
    public Coord idx;

    public CBlkCoordInfo() {
        this.idx = new Coord();
    }

    public CBlkCoordInfo(int m, int n) {
        this.idx = new Coord(n, m);
    }

    public String toString() {
        return super.toString() + ",idx=" + this.idx;
    }
}
