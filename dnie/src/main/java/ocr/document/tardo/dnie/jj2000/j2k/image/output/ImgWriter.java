package jj2000.j2k.image.output;

import java.io.IOException;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.Coord;

public abstract class ImgWriter {
    public static final int DEF_STRIP_HEIGHT = 64;
    /* renamed from: h */
    protected int f40h;
    protected BlkImgDataSrc src;
    /* renamed from: w */
    protected int f41w;

    public abstract void close() throws IOException;

    public abstract void flush() throws IOException;

    public abstract void write() throws IOException;

    public abstract void write(int i, int i2, int i3, int i4) throws IOException;

    public void finalize() throws IOException {
        flush();
    }

    public void writeAll() throws IOException {
        Coord nT = this.src.getNumTiles(null);
        System.out.println("nTiles = " + nT);
        for (int y = 0; y < nT.f37y; y++) {
            for (int x = 0; x < nT.f36x; x++) {
                System.out.println("setTiles(x,y) = " + x + ", " + y);
                this.src.setTile(x, y);
                write();
            }
        }
    }
}
