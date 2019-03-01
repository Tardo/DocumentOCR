package jj2000.j2k.image.output;

import java.io.IOException;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.Coord;
import jj2000.j2k.image.DataBlkInt;

public class ImgWriterArray extends ImgWriter {
    private int bitDepth;
    /* renamed from: c */
    private int f217c;
    private DataBlkInt db = new DataBlkInt();
    boolean isSigned;
    private int packBytes;

    public ImgWriterArray(BlkImgDataSrc imgSrc, int c, boolean isSigned) throws IOException {
        this.f217c = c;
        this.isSigned = isSigned;
        this.src = imgSrc;
        this.w = this.src.getImgWidth();
        this.h = this.src.getImgHeight();
        this.bitDepth = this.src.getNomRangeBits(this.f217c);
        if (this.bitDepth <= 0 || this.bitDepth > 31) {
            throw new IOException("Array supports only bit-depth between 1 and 31");
        } else if (this.bitDepth <= 8) {
            this.packBytes = 1;
        } else if (this.bitDepth <= 16) {
            this.packBytes = 2;
        } else {
            this.packBytes = 4;
        }
    }

    public void close() throws IOException {
    }

    public void write(int ulx, int uly, int w, int h) throws IOException {
        this.db.ulx = ulx;
        this.db.uly = uly;
        this.db.w = w;
        this.db.h = h;
        if (this.db.data != null && this.db.data.length < w * h) {
            this.db.data = null;
        }
        do {
            this.db = (DataBlkInt) this.src.getInternCompData(this.db, this.f217c);
        } while (this.db.progressive);
    }

    public void writeAll() throws IOException {
        Coord nT = this.src.getNumTiles(null);
        for (int y = 0; y < nT.f37y; y++) {
            for (int x = 0; x < nT.f36x; x++) {
                this.src.setTile(x, y);
                write(0, 0, this.src.getImgWidth(), this.src.getImgHeight());
            }
        }
    }

    public void write() throws IOException {
        int tIdx = this.src.getTileIdx();
        int tw = this.src.getTileCompWidth(tIdx, this.f217c);
        int th = this.src.getTileCompHeight(tIdx, this.f217c);
        for (int i = 0; i < th; i += 64) {
            int i2;
            if (th - i < 64) {
                i2 = th - i;
            } else {
                i2 = 64;
            }
            write(0, i, tw, i2);
        }
    }

    public int getPackBytes() {
        return this.packBytes;
    }

    public int[] getGdata() {
        return this.db.data;
    }

    public void flush() {
    }

    public String toString() {
        return "ImgWriterArray: WxH = " + this.w + "x" + this.h + ", Component = " + this.f217c + ", Bit-depth = " + this.bitDepth + ", signed = " + this.isSigned + "\nUnderlying RandomAccessFile:\n" + this.db.data.toString();
    }
}
