package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.image.Coord;

public abstract class MultiResImgDataAdapter implements MultiResImgData {
    protected MultiResImgData mressrc;
    protected int tIdx = 0;

    protected MultiResImgDataAdapter(MultiResImgData src) {
        this.mressrc = src;
    }

    public int getTileWidth(int rl) {
        return this.mressrc.getTileWidth(rl);
    }

    public int getTileHeight(int rl) {
        return this.mressrc.getTileHeight(rl);
    }

    public int getNomTileWidth() {
        return this.mressrc.getNomTileWidth();
    }

    public int getNomTileHeight() {
        return this.mressrc.getNomTileHeight();
    }

    public int getImgWidth(int rl) {
        return this.mressrc.getImgWidth(rl);
    }

    public int getImgHeight(int rl) {
        return this.mressrc.getImgHeight(rl);
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

    public int getTileCompWidth(int t, int c, int rl) {
        return this.mressrc.getTileCompWidth(t, c, rl);
    }

    public int getTileCompHeight(int t, int c, int rl) {
        return this.mressrc.getTileCompHeight(t, c, rl);
    }

    public int getCompImgWidth(int c, int rl) {
        return this.mressrc.getCompImgWidth(c, rl);
    }

    public int getCompImgHeight(int c, int rl) {
        return this.mressrc.getCompImgHeight(c, rl);
    }

    public void setTile(int x, int y) {
        this.mressrc.setTile(x, y);
        this.tIdx = getTileIdx();
    }

    public void nextTile() {
        this.mressrc.nextTile();
        this.tIdx = getTileIdx();
    }

    public Coord getTile(Coord co) {
        return this.mressrc.getTile(co);
    }

    public int getTileIdx() {
        return this.mressrc.getTileIdx();
    }

    public int getResULX(int c, int rl) {
        return this.mressrc.getResULX(c, rl);
    }

    public int getResULY(int c, int rl) {
        return this.mressrc.getResULY(c, rl);
    }

    public int getTilePartULX() {
        return this.mressrc.getTilePartULX();
    }

    public int getTilePartULY() {
        return this.mressrc.getTilePartULY();
    }

    public int getImgULX(int rl) {
        return this.mressrc.getImgULX(rl);
    }

    public int getImgULY(int rl) {
        return this.mressrc.getImgULY(rl);
    }

    public Coord getNumTiles(Coord co) {
        return this.mressrc.getNumTiles(co);
    }

    public int getNumTiles() {
        return this.mressrc.getNumTiles();
    }
}
