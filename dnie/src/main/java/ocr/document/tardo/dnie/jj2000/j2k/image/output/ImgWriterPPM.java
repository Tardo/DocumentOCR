package jj2000.j2k.image.output;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlkInt;

public class ImgWriterPPM extends ImgWriter {
    private byte[] buf;
    private int[] cps;
    private DataBlkInt db;
    private int[] fb;
    private int[] levShift;
    private int offset;
    private RandomAccessFile out;

    public ImgWriterPPM(File out, BlkImgDataSrc imgSrc, int n1, int n2, int n3) throws IOException {
        this.levShift = new int[3];
        this.cps = new int[3];
        this.fb = new int[3];
        this.db = new DataBlkInt();
        if (n1 < 0 || n1 >= imgSrc.getNumComps() || n2 < 0 || n2 >= imgSrc.getNumComps() || n3 < 0 || n3 >= imgSrc.getNumComps() || imgSrc.getNomRangeBits(n1) > 8 || imgSrc.getNomRangeBits(n2) > 8 || imgSrc.getNomRangeBits(n3) > 8) {
            throw new IllegalArgumentException("Invalid component indexes");
        }
        this.w = imgSrc.getCompImgWidth(n1);
        this.h = imgSrc.getCompImgHeight(n1);
        if (this.w == imgSrc.getCompImgWidth(n2) && this.w == imgSrc.getCompImgWidth(n3) && this.h == imgSrc.getCompImgHeight(n2) && this.h == imgSrc.getCompImgHeight(n3)) {
            this.w = imgSrc.getImgWidth();
            this.h = imgSrc.getImgHeight();
            if (!out.exists() || out.delete()) {
                this.out = new RandomAccessFile(out, "rw");
                this.src = imgSrc;
                this.cps[0] = n1;
                this.cps[1] = n2;
                this.cps[2] = n3;
                this.fb[0] = imgSrc.getFixedPoint(n1);
                this.fb[1] = imgSrc.getFixedPoint(n2);
                this.fb[2] = imgSrc.getFixedPoint(n3);
                this.levShift[0] = 1 << (imgSrc.getNomRangeBits(n1) - 1);
                this.levShift[1] = 1 << (imgSrc.getNomRangeBits(n2) - 1);
                this.levShift[2] = 1 << (imgSrc.getNomRangeBits(n3) - 1);
                writeHeaderInfo();
                return;
            }
            throw new IOException("Could not reset file");
        }
        throw new IllegalArgumentException("All components must have the same dimensions and no subsampling");
    }

    public ImgWriterPPM(String fname, BlkImgDataSrc imgSrc, int n1, int n2, int n3) throws IOException {
        this(new File(fname), imgSrc, n1, n2, n3);
    }

    public void close() throws IOException {
        if (this.out.length() != ((long) (((this.w * 3) * this.h) + this.offset))) {
            this.out.seek(this.out.length());
            for (int i = (((this.w * 3) * this.h) + this.offset) - ((int) this.out.length()); i > 0; i--) {
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
        int tOffx = this.src.getCompULX(this.cps[0]) - ((int) Math.ceil(((double) this.src.getImgULX()) / ((double) this.src.getCompSubsX(this.cps[0]))));
        int tOffy = this.src.getCompULY(this.cps[0]) - ((int) Math.ceil(((double) this.src.getImgULY()) / ((double) this.src.getCompSubsY(this.cps[0]))));
        if (this.db.data != null && this.db.data.length < w) {
            this.db.data = null;
        }
        if (this.buf == null || this.buf.length < w * 3) {
            this.buf = new byte[(w * 3)];
        }
        for (int i = 0; i < h; i++) {
            for (int c = 0; c < 3; c++) {
                int maxVal = (1 << this.src.getNomRangeBits(this.cps[c])) - 1;
                int shift = this.levShift[c];
                this.db.ulx = ulx;
                this.db.uly = uly + i;
                this.db.w = w;
                this.db.h = 1;
                do {
                    this.db = (DataBlkInt) this.src.getInternCompData(this.db, this.cps[c]);
                } while (this.db.progressive);
                int fracbits = this.fb[c];
                int k;
                int j;
                int tmp;
                byte[] bArr;
                if (fracbits == 0) {
                    k = (this.db.offset + w) - 1;
                    j = (((w * 3) - 1) + c) - 2;
                    while (j >= 0) {
                        tmp = this.db.data[k] + shift;
                        bArr = this.buf;
                        if (tmp < 0) {
                            tmp = 0;
                        } else if (tmp > maxVal) {
                            tmp = maxVal;
                        }
                        bArr[j] = (byte) tmp;
                        j -= 3;
                        k--;
                    }
                } else {
                    k = (this.db.offset + w) - 1;
                    j = (((w * 3) - 1) + c) - 2;
                    while (j >= 0) {
                        tmp = (this.db.data[k] >>> fracbits) + shift;
                        bArr = this.buf;
                        if (tmp < 0) {
                            tmp = 0;
                        } else if (tmp > maxVal) {
                            tmp = maxVal;
                        }
                        bArr[j] = (byte) tmp;
                        j -= 3;
                        k--;
                    }
                }
            }
            this.out.seek((long) (this.offset + ((((this.w * ((uly + tOffy) + i)) + ulx) + tOffx) * 3)));
            this.out.write(this.buf, 0, w * 3);
        }
    }

    public void write() throws IOException {
        int tIdx = this.src.getTileIdx();
        int tw = this.src.getTileCompWidth(tIdx, 0);
        int th = this.src.getTileCompHeight(tIdx, 0);
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
        this.out.seek(0);
        this.out.write(80);
        this.out.write(54);
        this.out.write(10);
        this.offset = 3;
        byte[] byteVals = String.valueOf(this.w).getBytes();
        for (byte write : byteVals) {
            this.out.write(write);
            this.offset++;
        }
        this.out.write(32);
        this.offset++;
        byteVals = String.valueOf(this.h).getBytes();
        for (byte write2 : byteVals) {
            this.out.write(write2);
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
        return "ImgWriterPPM: WxH = " + this.w + "x" + this.h + ", Components = " + this.cps[0] + "," + this.cps[1] + "," + this.cps[2] + "\nUnderlying RandomAccessFile:\n" + this.out.toString();
    }
}
