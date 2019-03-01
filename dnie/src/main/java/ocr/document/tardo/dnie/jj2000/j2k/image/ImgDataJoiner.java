package jj2000.j2k.image;

import jj2000.j2k.NoNextElementException;

public class ImgDataJoiner implements BlkImgDataSrc {
    private int[] compIdx;
    /* renamed from: h */
    private int f436h;
    private BlkImgDataSrc[] imageData;
    private int nc;
    private int[] subsX;
    private int[] subsY;
    /* renamed from: w */
    private int f437w;

    public ImgDataJoiner(BlkImgDataSrc[] imD, int[] cIdx) {
        this.imageData = imD;
        this.compIdx = cIdx;
        if (this.imageData.length != this.compIdx.length) {
            throw new IllegalArgumentException("imD and cIdx must have the same length");
        }
        this.nc = imD.length;
        this.subsX = new int[this.nc];
        this.subsY = new int[this.nc];
        int i = 0;
        while (i < this.nc) {
            if (imD[i].getNumTiles() == 1 && imD[i].getCompULX(cIdx[i]) == 0 && imD[i].getCompULY(cIdx[i]) == 0) {
                i++;
            } else {
                throw new IllegalArgumentException("All input components must, not use tiles and must have the origin at the canvas origin");
            }
        }
        int maxW = 0;
        int maxH = 0;
        for (i = 0; i < this.nc; i++) {
            if (imD[i].getCompImgWidth(cIdx[i]) > maxW) {
                maxW = imD[i].getCompImgWidth(cIdx[i]);
            }
            if (imD[i].getCompImgHeight(cIdx[i]) > maxH) {
                maxH = imD[i].getCompImgHeight(cIdx[i]);
            }
        }
        this.f437w = maxW;
        this.f436h = maxH;
        i = 0;
        while (i < this.nc) {
            this.subsX[i] = ((imD[i].getCompImgWidth(cIdx[i]) + maxW) - 1) / imD[i].getCompImgWidth(cIdx[i]);
            this.subsY[i] = ((imD[i].getCompImgHeight(cIdx[i]) + maxH) - 1) / imD[i].getCompImgHeight(cIdx[i]);
            if (((this.subsX[i] + maxW) - 1) / this.subsX[i] == imD[i].getCompImgWidth(cIdx[i]) && ((this.subsY[i] + maxH) - 1) / this.subsY[i] == imD[i].getCompImgHeight(cIdx[i])) {
                i++;
            } else {
                throw new Error("Can not compute component subsampling factors: strange subsampling.");
            }
        }
    }

    public int getTileWidth() {
        return this.f437w;
    }

    public int getTileHeight() {
        return this.f436h;
    }

    public int getNomTileWidth() {
        return this.f437w;
    }

    public int getNomTileHeight() {
        return this.f436h;
    }

    public int getImgWidth() {
        return this.f437w;
    }

    public int getImgHeight() {
        return this.f436h;
    }

    public int getNumComps() {
        return this.nc;
    }

    public int getCompSubsX(int c) {
        return this.subsX[c];
    }

    public int getCompSubsY(int c) {
        return this.subsY[c];
    }

    public int getTileCompWidth(int t, int c) {
        return this.imageData[c].getTileCompWidth(t, this.compIdx[c]);
    }

    public int getTileCompHeight(int t, int c) {
        return this.imageData[c].getTileCompHeight(t, this.compIdx[c]);
    }

    public int getCompImgWidth(int c) {
        return this.imageData[c].getCompImgWidth(this.compIdx[c]);
    }

    public int getCompImgHeight(int n) {
        return this.imageData[n].getCompImgHeight(this.compIdx[n]);
    }

    public int getNomRangeBits(int c) {
        return this.imageData[c].getNomRangeBits(this.compIdx[c]);
    }

    public int getFixedPoint(int c) {
        return this.imageData[c].getFixedPoint(this.compIdx[c]);
    }

    public DataBlk getInternCompData(DataBlk blk, int c) {
        return this.imageData[c].getInternCompData(blk, this.compIdx[c]);
    }

    public DataBlk getCompData(DataBlk blk, int c) {
        return this.imageData[c].getCompData(blk, this.compIdx[c]);
    }

    public void setTile(int x, int y) {
        if (x != 0 || y != 0) {
            throw new IllegalArgumentException();
        }
    }

    public void nextTile() {
        throw new NoNextElementException();
    }

    public Coord getTile(Coord co) {
        if (co == null) {
            return new Coord(0, 0);
        }
        co.f36x = 0;
        co.f37y = 0;
        return co;
    }

    public int getTileIdx() {
        return 0;
    }

    public int getCompULX(int c) {
        return 0;
    }

    public int getCompULY(int c) {
        return 0;
    }

    public int getTilePartULX() {
        return 0;
    }

    public int getTilePartULY() {
        return 0;
    }

    public int getImgULX() {
        return 0;
    }

    public int getImgULY() {
        return 0;
    }

    public Coord getNumTiles(Coord co) {
        if (co == null) {
            return new Coord(1, 1);
        }
        co.f36x = 1;
        co.f37y = 1;
        return co;
    }

    public int getNumTiles() {
        return 1;
    }

    public String toString() {
        String string = "ImgDataJoiner: WxH = " + this.f437w + "x" + this.f436h;
        for (int i = 0; i < this.nc; i++) {
            string = string + "\n- Component " + i + " " + this.imageData[i];
        }
        return string;
    }
}
