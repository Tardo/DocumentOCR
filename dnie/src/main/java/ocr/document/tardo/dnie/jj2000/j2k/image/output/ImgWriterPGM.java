package jj2000.j2k.image.output;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.FacilityManager;

public class ImgWriterPGM extends ImgWriter {
    private byte[] buf;
    /* renamed from: c */
    private int f218c;
    private DataBlkInt db;
    private int fb;
    private int levShift;
    private int offset;
    private RandomAccessFile out;

    public ImgWriterPGM(File out, BlkImgDataSrc imgSrc, int c) throws IOException {
        this.db = new DataBlkInt();
        if (c < 0 || c >= imgSrc.getNumComps()) {
            throw new IllegalArgumentException("Invalid number of components");
        }
        if (imgSrc.getNomRangeBits(c) > 8) {
            FacilityManager.getMsgLogger().println("Warning: Component " + c + " has nominal bitdepth " + imgSrc.getNomRangeBits(c) + ". Pixel values will be " + "down-shifted to fit bitdepth of 8 for PGM file", 8, 8);
        }
        if (!out.exists() || out.delete()) {
            this.out = new RandomAccessFile(out, "rw");
            this.src = imgSrc;
            this.f218c = c;
            this.w = imgSrc.getImgWidth();
            this.h = imgSrc.getImgHeight();
            this.fb = imgSrc.getFixedPoint(c);
            this.levShift = 1 << (imgSrc.getNomRangeBits(c) - 1);
            writeHeaderInfo();
            return;
        }
        throw new IOException("Could not reset file");
    }

    public ImgWriterPGM(String fname, BlkImgDataSrc imgSrc, int c) throws IOException {
        this(new File(fname), imgSrc, c);
    }

    public void close() throws IOException {
        if (this.out.length() != ((long) ((this.w * this.h) + this.offset))) {
            this.out.seek(this.out.length());
            for (int i = (this.offset + (this.w * this.h)) - ((int) this.out.length()); i > 0; i--) {
                this.out.writeByte(0);
            }
        }
        this.out.close();
        this.src = null;
        this.out = null;
        this.db = null;
    }

    public void flush() throws IOException {
        this.buf = null;
    }

    public void write(int ulx, int uly, int w, int h) throws IOException {
        int fracbits = this.fb;
        this.db.ulx = ulx;
        this.db.uly = uly;
        this.db.w = w;
        this.db.h = h;
        int tOffx = this.src.getCompULX(this.f218c) - ((int) Math.ceil(((double) this.src.getImgULX()) / ((double) this.src.getCompSubsX(this.f218c))));
        int tOffy = this.src.getCompULY(this.f218c) - ((int) Math.ceil(((double) this.src.getImgULY()) / ((double) this.src.getCompSubsY(this.f218c))));
        if (this.db.data != null && this.db.data.length < w * h) {
            this.db.data = null;
        }
        do {
            this.db = (DataBlkInt) this.src.getInternCompData(this.db, this.f218c);
        } while (this.db.progressive);
        int maxVal = (1 << this.src.getNomRangeBits(this.f218c)) - 1;
        int downShift = this.src.getNomRangeBits(this.f218c) - 8;
        if (downShift < 0) {
            downShift = 0;
        }
        if (this.buf == null || this.buf.length < w) {
            this.buf = new byte[w];
        }
        for (int i = 0; i < h; i++) {
            this.out.seek((long) (((this.offset + (this.w * ((uly + tOffy) + i))) + ulx) + tOffx));
            int k;
            int j;
            int tmp;
            byte[] bArr;
            if (fracbits == 0) {
                k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                j = w - 1;
                while (j >= 0) {
                    tmp = this.db.data[k] + this.levShift;
                    bArr = this.buf;
                    if (tmp < 0) {
                        tmp = 0;
                    } else if (tmp > maxVal) {
                        tmp = maxVal;
                    }
                    bArr[j] = (byte) (tmp >> downShift);
                    j--;
                    k--;
                }
            } else {
                k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                j = w - 1;
                while (j >= 0) {
                    tmp = (this.db.data[k] >> fracbits) + this.levShift;
                    bArr = this.buf;
                    if (tmp < 0) {
                        tmp = 0;
                    } else if (tmp > maxVal) {
                        tmp = maxVal;
                    }
                    bArr[j] = (byte) (tmp >> downShift);
                    j--;
                    k--;
                }
            }
            this.out.write(this.buf, 0, w);
        }
    }

    public void write() throws IOException {
        int tIdx = this.src.getTileIdx();
        int tw = this.src.getTileCompWidth(tIdx, this.f218c);
        int th = this.src.getTileCompHeight(tIdx, this.f218c);
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

    private void writeHeaderInfo() throws IOException {
        this.out.writeByte(80);
        this.out.write(53);
        this.out.write(10);
        this.offset = 3;
        byte[] byteVals = String.valueOf(this.w).getBytes();
        for (byte writeByte : byteVals) {
            this.out.writeByte(writeByte);
            this.offset++;
        }
        this.out.write(32);
        this.offset++;
        byteVals = String.valueOf(this.h).getBytes();
        for (byte writeByte2 : byteVals) {
            this.out.writeByte(writeByte2);
            this.offset++;
        }
        this.out.write(10);
        this.out.write(50);
        this.out.write(53);
        this.out.write(53);
        this.out.write(10);
        this.offset += 5;
    }

    public String toString() {
        return "ImgWriterPGM: WxH = " + this.w + "x" + this.h + ", Component=" + this.f218c + "\nUnderlying RandomAccessFile:\n" + this.out.toString();
    }
}
