package jj2000.j2k.image;

public abstract class ImgDataAdapter implements ImgData {
    protected ImgData imgdatasrc;
    protected int tIdx = 0;

    protected ImgDataAdapter(ImgData src) {
        this.imgdatasrc = src;
    }

    public int getTileWidth() {
        return this.imgdatasrc.getTileWidth();
    }

    public int getTileHeight() {
        return this.imgdatasrc.getTileHeight();
    }

    public int getNomTileWidth() {
        return this.imgdatasrc.getNomTileWidth();
    }

    public int getNomTileHeight() {
        return this.imgdatasrc.getNomTileHeight();
    }

    public int getImgWidth() {
        return this.imgdatasrc.getImgWidth();
    }

    public int getImgHeight() {
        return this.imgdatasrc.getImgHeight();
    }

    public int getNumComps() {
        return this.imgdatasrc.getNumComps();
    }

    public int getCompSubsX(int c) {
        return this.imgdatasrc.getCompSubsX(c);
    }

    public int getCompSubsY(int c) {
        return this.imgdatasrc.getCompSubsY(c);
    }

    public int getTileCompWidth(int t, int c) {
        return this.imgdatasrc.getTileCompWidth(t, c);
    }

    public int getTileCompHeight(int t, int c) {
        return this.imgdatasrc.getTileCompHeight(t, c);
    }

    public int getCompImgWidth(int c) {
        return this.imgdatasrc.getCompImgWidth(c);
    }

    public int getCompImgHeight(int c) {
        return this.imgdatasrc.getCompImgHeight(c);
    }

    public int getNomRangeBits(int c) {
        return this.imgdatasrc.getNomRangeBits(c);
    }

    public void setTile(int x, int y) {
        this.imgdatasrc.setTile(x, y);
        this.tIdx = getTileIdx();
    }

    public void nextTile() {
        this.imgdatasrc.nextTile();
        this.tIdx = getTileIdx();
    }

    public Coord getTile(Coord co) {
        return this.imgdatasrc.getTile(co);
    }

    public int getTileIdx() {
        return this.imgdatasrc.getTileIdx();
    }

    public int getCompULX(int c) {
        return this.imgdatasrc.getCompULX(c);
    }

    public int getCompULY(int c) {
        return this.imgdatasrc.getCompULY(c);
    }

    public int getTilePartULX() {
        return this.imgdatasrc.getTilePartULX();
    }

    public int getTilePartULY() {
        return this.imgdatasrc.getTilePartULY();
    }

    public int getImgULX() {
        return this.imgdatasrc.getImgULX();
    }

    public int getImgULY() {
        return this.imgdatasrc.getImgULY();
    }

    public Coord getNumTiles(Coord co) {
        return this.imgdatasrc.getNumTiles(co);
    }

    public int getNumTiles() {
        return this.imgdatasrc.getNumTiles();
    }
}
