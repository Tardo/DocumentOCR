package jj2000.j2k.image.output;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlkInt;

public class ImgWriterPGX extends ImgWriter {
    private int bitDepth;
    private byte[] buf;
    /* renamed from: c */
    private int f219c;
    private DataBlkInt db;
    private int fb;
    boolean isSigned;
    int levShift;
    int maxVal;
    int minVal;
    private int offset;
    private RandomAccessFile out;
    private int packBytes;

    public ImgWriterPGX(File out, BlkImgDataSrc imgSrc, int c, boolean isSigned) throws IOException {
        int i = 0;
        this.db = new DataBlkInt();
        this.f219c = c;
        if (!out.exists() || out.delete()) {
            this.out = new RandomAccessFile(out, "rw");
            this.isSigned = isSigned;
            this.src = imgSrc;
            this.w = this.src.getImgWidth();
            this.h = this.src.getImgHeight();
            this.fb = imgSrc.getFixedPoint(c);
            this.bitDepth = this.src.getNomRangeBits(this.f219c);
            if (this.bitDepth <= 0 || this.bitDepth > 31) {
                throw new IOException("PGX supports only bit-depth between 1 and 31");
            }
            int nomRangeBits;
            if (this.bitDepth <= 8) {
                this.packBytes = 1;
            } else if (this.bitDepth <= 16) {
                this.packBytes = 2;
            } else {
                this.packBytes = 4;
            }
            byte[] tmpByte = ("PG ML " + (this.isSigned ? "- " : "+ ") + this.bitDepth + " " + this.w + " " + this.h + "\n").getBytes();
            for (byte write : tmpByte) {
                this.out.write(write);
            }
            this.offset = tmpByte.length;
            this.maxVal = this.isSigned ? (1 << (this.src.getNomRangeBits(c) - 1)) - 1 : (1 << this.src.getNomRangeBits(c)) - 1;
            if (this.isSigned) {
                nomRangeBits = (1 << (this.src.getNomRangeBits(c) - 1)) * -1;
            } else {
                nomRangeBits = 0;
            }
            this.minVal = nomRangeBits;
            if (!this.isSigned) {
                i = 1 << (this.src.getNomRangeBits(c) - 1);
            }
            this.levShift = i;
            return;
        }
        throw new IOException("Could not reset file");
    }

    public ImgWriterPGX(String fname, BlkImgDataSrc imgSrc, int c, boolean isSigned) throws IOException {
        this(new File(fname), imgSrc, c, isSigned);
    }

    public void close() throws IOException {
        if (this.out.length() != ((long) (((this.w * this.h) * this.packBytes) + this.offset))) {
            this.out.seek(this.out.length());
            for (int i = (this.offset + ((this.w * this.h) * this.packBytes)) - ((int) this.out.length()); i > 0; i--) {
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
        int tOffx = this.src.getCompULX(this.f219c) - ((int) Math.ceil(((double) this.src.getImgULX()) / ((double) this.src.getCompSubsX(this.f219c))));
        int tOffy = this.src.getCompULY(this.f219c) - ((int) Math.ceil(((double) this.src.getImgULY()) / ((double) this.src.getCompSubsY(this.f219c))));
        if (this.db.data != null && this.db.data.length < w * h) {
            this.db.data = null;
        }
        do {
            this.db = (DataBlkInt) this.src.getInternCompData(this.db, this.f219c);
        } while (this.db.progressive);
        if (this.buf == null || this.buf.length < this.packBytes * w) {
            this.buf = new byte[(this.packBytes * w)];
        }
        int i;
        int k;
        int j;
        int tmp;
        int j2;
        switch (this.packBytes) {
            case 1:
                for (i = 0; i < h; i++) {
                    this.out.seek((long) (((this.offset + (this.w * ((uly + tOffy) + i))) + ulx) + tOffx));
                    byte[] bArr;
                    if (fracbits == 0) {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = w - 1;
                        while (j >= 0) {
                            tmp = this.db.data[k] + this.levShift;
                            bArr = this.buf;
                            j2 = j - 1;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            bArr[j] = (byte) tmp;
                            k--;
                            j = j2;
                        }
                    } else {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = w - 1;
                        while (j >= 0) {
                            tmp = (this.db.data[k] >>> fracbits) + this.levShift;
                            bArr = this.buf;
                            j2 = j - 1;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            bArr[j] = (byte) tmp;
                            k--;
                            j = j2;
                        }
                    }
                    this.out.write(this.buf, 0, w);
                }
                return;
            case 2:
                for (i = 0; i < h; i++) {
                    this.out.seek((long) (this.offset + ((((this.w * ((uly + tOffy) + i)) + ulx) + tOffx) * 2)));
                    if (fracbits == 0) {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = (w << 1) - 1;
                        while (j >= 0) {
                            tmp = this.db.data[k] + this.levShift;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            j2 = j - 1;
                            this.buf[j] = (byte) tmp;
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 8);
                            k--;
                        }
                    } else {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = (w << 1) - 1;
                        while (j >= 0) {
                            tmp = (this.db.data[k] >>> fracbits) + this.levShift;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            j2 = j - 1;
                            this.buf[j] = (byte) tmp;
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 8);
                            k--;
                        }
                    }
                    j2 = j;
                    this.out.write(this.buf, 0, w << 1);
                }
                return;
            case 4:
                for (i = 0; i < h; i++) {
                    this.out.seek((long) (this.offset + ((((this.w * ((uly + tOffy) + i)) + ulx) + tOffx) * 4)));
                    if (fracbits == 0) {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = (w << 2) - 1;
                        while (j >= 0) {
                            tmp = this.db.data[k] + this.levShift;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            j2 = j - 1;
                            this.buf[j] = (byte) tmp;
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 8);
                            j2 = j - 1;
                            this.buf[j] = (byte) (tmp >>> 16);
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 24);
                            k--;
                        }
                    } else {
                        k = ((this.db.offset + (this.db.scanw * i)) + w) - 1;
                        j = (w << 2) - 1;
                        while (j >= 0) {
                            tmp = (this.db.data[k] >>> fracbits) + this.levShift;
                            if (tmp < this.minVal) {
                                tmp = this.minVal;
                            } else if (tmp > this.maxVal) {
                                tmp = this.maxVal;
                            }
                            j2 = j - 1;
                            this.buf[j] = (byte) tmp;
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 8);
                            j2 = j - 1;
                            this.buf[j] = (byte) (tmp >>> 16);
                            j = j2 - 1;
                            this.buf[j2] = (byte) (tmp >>> 24);
                            k--;
                        }
                    }
                    j2 = j;
                    this.out.write(this.buf, 0, w << 2);
                }
                return;
            default:
                throw new IOException("PGX supports only bit-depth between 1 and 31");
        }
    }

    public void write() throws IOException {
        int tIdx = this.src.getTileIdx();
        int tw = this.src.getTileCompWidth(tIdx, this.f219c);
        int th = this.src.getTileCompHeight(tIdx, this.f219c);
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

    public String toString() {
        return "ImgWriterPGX: WxH = " + this.w + "x" + this.h + ", Component = " + this.f219c + ", Bit-depth = " + this.bitDepth + ", signed = " + this.isSigned + "\nUnderlying RandomAccessFile:\n" + this.out.toString();
    }
}
