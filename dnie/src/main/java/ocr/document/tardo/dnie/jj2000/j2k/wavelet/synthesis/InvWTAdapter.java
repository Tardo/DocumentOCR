package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.Coord;

public abstract class InvWTAdapter implements InvWT {
    protected DecoderSpecs decSpec;
    protected int maxImgRes;
    protected MultiResImgData mressrc;
    protected int reslvl;

    protected InvWTAdapter(MultiResImgData src, DecoderSpecs decSpec) {
        this.mressrc = src;
        this.decSpec = decSpec;
        this.maxImgRes = decSpec.dls.getMin();
    }

    public void setImgResLevel(int rl) {
        if (rl < 0) {
            throw new IllegalArgumentException("Resolution level index cannot be negative.");
        }
        this.reslvl = rl;
    }

    public int getTileWidth() {
        int tIdx = getTileIdx();
        int rl = 10000;
        int nc = this.mressrc.getNumComps();
        for (int c = 0; c < nc; c++) {
            int mrl = this.mressrc.getSynSubbandTree(tIdx, c).resLvl;
            if (mrl < rl) {
                rl = mrl;
            }
        }
        return this.mressrc.getTileWidth(rl);
    }

    public int getTileHeight() {
        int tIdx = getTileIdx();
        int rl = 10000;
        int nc = this.mressrc.getNumComps();
        for (int c = 0; c < nc; c++) {
            int mrl = this.mressrc.getSynSubbandTree(tIdx, c).resLvl;
            if (mrl < rl) {
                rl = mrl;
            }
        }
        return this.mressrc.getTileHeight(rl);
    }

    public int getNomTileWidth() {
        return this.mressrc.getNomTileWidth();
    }

    public int getNomTileHeight() {
        return this.mressrc.getNomTileHeight();
    }

    public int getImgWidth() {
        return this.mressrc.getImgWidth(this.reslvl);
    }

    public int getImgHeight() {
        return this.mressrc.getImgHeight(this.reslvl);
    }

    public int getNumComps() {
        return this.mressrc.getNumComps();
    }

    public int getCompSubsX(int c) {
        return this.mressrc.getCompSubsX(c);
    }

    public int getCompSubsY(int c) {
        return this.mressrc.getCompSubsY(c);
    }

    public int getTileCompWidth(int t, int c) {
        return this.mressrc.getTileCompWidth(t, c, this.mressrc.getSynSubbandTree(t, c).resLvl);
    }

    public int getTileCompHeight(int t, int c) {
        return this.mressrc.getTileCompHeight(t, c, this.mressrc.getSynSubbandTree(t, c).resLvl);
    }

    public int getCompImgWidth(int c) {
        return this.mressrc.getCompImgWidth(c, this.decSpec.dls.getMinInComp(c));
    }

    public int getCompImgHeight(int c) {
        return this.mressrc.getCompImgHeight(c, this.decSpec.dls.getMinInComp(c));
    }

    public void setTile(int x, int y) {
        this.mressrc.setTile(x, y);
    }

    public void nextTile() {
        this.mressrc.nextTile();
    }

    public Coord getTile(Coord co) {
        return this.mressrc.getTile(co);
    }

    public int getTileIdx() {
        return this.mressrc.getTileIdx();
    }

    public int getCompULX(int c) {
        return this.mressrc.getResULX(c, this.mressrc.getSynSubbandTree(getTileIdx(), c).resLvl);
    }

    public int getCompULY(int c) {
        return this.mressrc.getResULY(c, this.mressrc.getSynSubbandTree(getTileIdx(), c).resLvl);
    }

    public int getImgULX() {
        return this.mressrc.getImgULX(this.reslvl);
    }

    public int getImgULY() {
        return this.mressrc.getImgULY(this.reslvl);
    }

    public int getTilePartULX() {
        return this.mressrc.getTilePartULX();
    }

    public int getTilePartULY() {
        return this.mressrc.getTilePartULY();
    }

    public Coord getNumTiles(Coord co) {
        return this.mressrc.getNumTiles(co);
    }

    public int getNumTiles() {
        return this.mressrc.getNumTiles();
    }

    public SubbandSyn getSynSubbandTree(int t, int c) {
        return this.mressrc.getSynSubbandTree(t, c);
    }
}
