package jj2000.j2k.image;

import jj2000.j2k.NoNextElementException;
import jj2000.j2k.util.FacilityManager;

public class Tiler extends ImgDataAdapter implements BlkImgDataSrc {
    private int[] compH = null;
    private int[] compW = null;
    private int ntX;
    private int ntY;
    private BlkImgDataSrc src = null;
    private int[] tcx0 = null;
    private int[] tcy0 = null;
    private int tileH;
    private int tileW;
    private int tx;
    private int ty;
    private int x0siz;
    private int xt0siz;
    private int xtsiz;
    private int y0siz;
    private int yt0siz;
    private int ytsiz;

    public Tiler(BlkImgDataSrc src, int ax, int ay, int px, int py, int nw, int nh) {
        super(src);
        this.src = src;
        this.x0siz = ax;
        this.y0siz = ay;
        this.xt0siz = px;
        this.yt0siz = py;
        this.xtsiz = nw;
        this.ytsiz = nh;
        if (src.getNumTiles() != 1) {
            throw new IllegalArgumentException("Source is tiled");
        } else if (src.getImgULX() != 0 || src.getImgULY() != 0) {
            throw new IllegalArgumentException("Source is \"canvased\"");
        } else if (this.x0siz < 0 || this.y0siz < 0 || this.xt0siz < 0 || this.yt0siz < 0 || this.xtsiz < 0 || this.ytsiz < 0 || this.xt0siz > this.x0siz || this.yt0siz > this.y0siz) {
            throw new IllegalArgumentException("Invalid image origin, tiling origin or nominal tile size");
        } else {
            if (this.xtsiz == 0) {
                this.xtsiz = (this.x0siz + src.getImgWidth()) - this.xt0siz;
            }
            if (this.ytsiz == 0) {
                this.ytsiz = (this.y0siz + src.getImgHeight()) - this.yt0siz;
            }
            if (this.x0siz - this.xt0siz >= this.xtsiz) {
                this.xt0siz += ((this.x0siz - this.xt0siz) / this.xtsiz) * this.xtsiz;
            }
            if (this.y0siz - this.yt0siz >= this.ytsiz) {
                this.yt0siz += ((this.y0siz - this.yt0siz) / this.ytsiz) * this.ytsiz;
            }
            if (this.x0siz - this.xt0siz >= this.xtsiz || this.y0siz - this.yt0siz >= this.ytsiz) {
                FacilityManager.getMsgLogger().printmsg(1, "Automatically adjusted tiling origin to equivalent one (" + this.xt0siz + "," + this.yt0siz + ") so that " + "first tile overlaps the image");
            }
            this.ntX = (int) Math.ceil(((double) (this.x0siz + src.getImgWidth())) / ((double) this.xtsiz));
            this.ntY = (int) Math.ceil(((double) (this.y0siz + src.getImgHeight())) / ((double) this.ytsiz));
        }
    }

    public final int getTileWidth() {
        return this.tileW;
    }

    public final int getTileHeight() {
        return this.tileH;
    }

    public final int getTileCompWidth(int t, int c) {
        if (t == getTileIdx()) {
            return this.compW[c];
        }
        throw new Error("Asking the width of a tile-component which is not in the current tile (call setTile() or nextTile() methods before).");
    }

    public final int getTileCompHeight(int t, int c) {
        if (t == getTileIdx()) {
            return this.compH[c];
        }
        throw new Error("Asking the width of a tile-component which is not in the current tile (call setTile() or nextTile() methods before).");
    }

    public int getFixedPoint(int c) {
        return this.src.getFixedPoint(c);
    }

    public final DataBlk getInternCompData(DataBlk blk, int c) {
        if (blk.ulx < 0 || blk.uly < 0 || blk.f39w > this.compW[c] || blk.f38h > this.compH[c]) {
            throw new IllegalArgumentException("Block is outside the tile");
        }
        int incx = (int) Math.ceil(((double) this.x0siz) / ((double) this.src.getCompSubsX(c)));
        int incy = (int) Math.ceil(((double) this.y0siz) / ((double) this.src.getCompSubsY(c)));
        blk.ulx -= incx;
        blk.uly -= incy;
        blk = this.src.getInternCompData(blk, c);
        blk.ulx += incx;
        blk.uly += incy;
        return blk;
    }

    public final DataBlk getCompData(DataBlk blk, int c) {
        if (blk.ulx < 0 || blk.uly < 0 || blk.f39w > this.compW[c] || blk.f38h > this.compH[c]) {
            throw new IllegalArgumentException("Block is outside the tile");
        }
        int incx = (int) Math.ceil(((double) this.x0siz) / ((double) this.src.getCompSubsX(c)));
        int incy = (int) Math.ceil(((double) this.y0siz) / ((double) this.src.getCompSubsY(c)));
        blk.ulx -= incx;
        blk.uly -= incy;
        blk = this.src.getCompData(blk, c);
        blk.ulx += incx;
        blk.uly += incy;
        return blk;
    }

    public final void setTile(int x, int y) {
        if (x < 0 || y < 0 || x >= this.ntX || y >= this.ntY) {
            throw new IllegalArgumentException("Tile's indexes out of bounds");
        }
        int ty1;
        this.tx = x;
        this.ty = y;
        int tx0 = x != 0 ? this.xt0siz + (this.xtsiz * x) : this.x0siz;
        int ty0 = y != 0 ? this.yt0siz + (this.ytsiz * y) : this.y0siz;
        int tx1 = x != this.ntX + -1 ? this.xt0siz + ((x + 1) * this.xtsiz) : this.x0siz + this.src.getImgWidth();
        if (y != this.ntY - 1) {
            ty1 = this.yt0siz + ((y + 1) * this.ytsiz);
        } else {
            ty1 = this.y0siz + this.src.getImgHeight();
        }
        this.tileW = tx1 - tx0;
        this.tileH = ty1 - ty0;
        int nc = this.src.getNumComps();
        if (this.compW == null) {
            this.compW = new int[nc];
        }
        if (this.compH == null) {
            this.compH = new int[nc];
        }
        if (this.tcx0 == null) {
            this.tcx0 = new int[nc];
        }
        if (this.tcy0 == null) {
            this.tcy0 = new int[nc];
        }
        for (int i = 0; i < nc; i++) {
            this.tcx0[i] = (int) Math.ceil(((double) tx0) / ((double) this.src.getCompSubsX(i)));
            this.tcy0[i] = (int) Math.ceil(((double) ty0) / ((double) this.src.getCompSubsY(i)));
            this.compW[i] = ((int) Math.ceil(((double) tx1) / ((double) this.src.getCompSubsX(i)))) - this.tcx0[i];
            this.compH[i] = ((int) Math.ceil(((double) ty1) / ((double) this.src.getCompSubsY(i)))) - this.tcy0[i];
        }
    }

    public final void nextTile() {
        if (this.tx == this.ntX - 1 && this.ty == this.ntY - 1) {
            throw new NoNextElementException();
        } else if (this.tx < this.ntX - 1) {
            setTile(this.tx + 1, this.ty);
        } else {
            setTile(0, this.ty + 1);
        }
    }

    public final Coord getTile(Coord co) {
        if (co == null) {
            return new Coord(this.tx, this.ty);
        }
        co.f36x = this.tx;
        co.f37y = this.ty;
        return co;
    }

    public final int getTileIdx() {
        return (this.ty * this.ntX) + this.tx;
    }

    public final int getCompULX(int c) {
        return this.tcx0[c];
    }

    public final int getCompULY(int c) {
        return this.tcy0[c];
    }

    public int getTilePartULX() {
        return this.xt0siz;
    }

    public int getTilePartULY() {
        return this.yt0siz;
    }

    public final int getImgULX() {
        return this.x0siz;
    }

    public final int getImgULY() {
        return this.y0siz;
    }

    public final Coord getNumTiles(Coord co) {
        if (co == null) {
            return new Coord(this.ntX, this.ntY);
        }
        co.f36x = this.ntX;
        co.f37y = this.ntY;
        return co;
    }

    public final int getNumTiles() {
        return this.ntX * this.ntY;
    }

    public final int getNomTileWidth() {
        return this.xtsiz;
    }

    public final int getNomTileHeight() {
        return this.ytsiz;
    }

    public final Coord getTilingOrigin(Coord co) {
        if (co == null) {
            return new Coord(this.xt0siz, this.yt0siz);
        }
        co.f36x = this.xt0siz;
        co.f37y = this.yt0siz;
        return co;
    }

    public String toString() {
        return "Tiler: source= " + this.src + "\n" + getNumTiles() + " tile(s), nominal width=" + this.xtsiz + ", nominal height=" + this.ytsiz;
    }
}
