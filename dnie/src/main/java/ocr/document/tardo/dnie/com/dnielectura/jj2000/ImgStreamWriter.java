package com.dnielectura.jj2000;

import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.image.output.ImgWriter;

public class ImgStreamWriter extends ImgWriter {
    private final int CAPACITY = 5000000;
    private byte[] buf;
    private ByteBuffer buffer = ByteBuffer.allocate(5000000);
    private int[] cps = new int[3];
    private DataBlkInt db = new DataBlkInt();
    private int[] fb = new int[3];
    private int[] levShift = new int[3];
    private int offset;

    private class PPMConverter {
        InputStream is;

        private PPMConverter(InputStream is) {
            this.is = is;
        }

        public Bitmap createBufferedImage() throws IOException {
            if (readUntilWhiteSpace(this.is).equals("P6")) {
                int width = Integer.parseInt(readUntilWhiteSpace(this.is));
                int height = Integer.parseInt(readUntilWhiteSpace(this.is));
                if (Integer.parseInt(readUntilWhiteSpace(this.is)) != 255) {
                    throw new IOException("This decoder only accepts 8-bit image depth");
                }
                Bitmap img = Bitmap.createBitmap(width, height, Config.ARGB_8888);
                int[] pixel = new int[3];
                for (int y = 0; y < height; y++) {
                    int x = 0;
                    while (x < width) {
                        int red = this.is.read();
                        int green = this.is.read();
                        int blue = this.is.read();
                        if (red > 255 || red < 0) {
                            throw new IOException();
                        } else if (green > 255 || green < 0) {
                            throw new IOException();
                        } else if (blue > 255 || blue < 0) {
                            throw new IOException();
                        } else {
                            pixel[0] = red;
                            pixel[1] = green;
                            pixel[2] = blue;
                            img.setPixel(x, y, getIntFromColor(pixel[0], pixel[1], pixel[2]));
                            x++;
                        }
                    }
                }
                return img;
            }
            throw new IOException();
        }

        public int getIntFromColor(int Red, int Green, int Blue) {
            Green = (Green << 8) & 65280;
            return ((-16777216 | ((Red << 16) & 16711680)) | Green) | (Blue & 255);
        }

        public String readUntilWhiteSpace(InputStream is) throws IOException {
            String data = "";
            char next = (char) is.read();
            while (true) {
                if (next != '\n' && next != ' ' && next != '\t') {
                    break;
                }
                next = (char) is.read();
            }
            while (next != '\n' && next != ' ' && next != '\t') {
                data = data + next;
                int b = is.read();
                if (b == -1) {
                    throw new IOException("Unexpected EOF while reading header");
                }
                next = (char) b;
            }
            return data;
        }
    }

    public ImgStreamWriter(BlkImgDataSrc imgSrc, int n1, int n2, int n3) throws IOException {
        if (n1 < 0 || n1 >= imgSrc.getNumComps() || n2 < 0 || n2 >= imgSrc.getNumComps() || n3 < 0 || n3 >= imgSrc.getNumComps() || imgSrc.getNomRangeBits(n1) > 8 || imgSrc.getNomRangeBits(n2) > 8 || imgSrc.getNomRangeBits(n3) > 8) {
            if (n1 >= imgSrc.getNumComps()) {
                n1 = 0;
            }
            if (n2 >= imgSrc.getNumComps()) {
                n2 = 0;
            }
            if (n3 >= imgSrc.getNumComps()) {
                n3 = 0;
            }
        }
        this.w = imgSrc.getCompImgWidth(n1);
        this.h = imgSrc.getCompImgHeight(n1);
        if (this.w == imgSrc.getCompImgWidth(n2) && this.w == imgSrc.getCompImgWidth(n3) && this.h == imgSrc.getCompImgHeight(n2) && this.h == imgSrc.getCompImgHeight(n3)) {
            this.w = imgSrc.getImgWidth();
            this.h = imgSrc.getImgHeight();
            this.buffer.clear();
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
        throw new IllegalArgumentException("All components must have the same dimensions and no subsampling");
    }

    public void close() throws IOException {
        this.src = null;
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
            this.buffer.position(this.offset + ((((this.w * ((uly + tOffy) + i)) + ulx) + tOffx) * 3));
            this.buffer.put(this.buf, 0, w * 3);
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
        this.buffer.position(0);
        this.buffer.put((byte) 80);
        this.buffer.put((byte) 54);
        this.buffer.put((byte) 10);
        this.offset = 3;
        byte[] byteVals = String.valueOf(this.w).getBytes();
        for (byte put : byteVals) {
            this.buffer.put(put);
            this.offset++;
        }
        this.buffer.put((byte) 32);
        this.offset++;
        byteVals = String.valueOf(this.h).getBytes();
        for (byte put2 : byteVals) {
            this.buffer.put(put2);
            this.offset++;
        }
        this.buffer.put((byte) 10);
        this.buffer.put((byte) 50);
        this.buffer.put((byte) 53);
        this.buffer.put((byte) 53);
        this.buffer.put((byte) 10);
        this.offset += 5;
    }

    public ByteArrayInputStream getByteArrayInputStream() {
        return new ByteArrayInputStream(Arrays.copyOf(this.buffer.array(), this.buffer.position()));
    }

    public Bitmap getImage() throws IOException {
        writeAll();
        return new PPMConverter(new ByteArrayInputStream(Arrays.copyOf(this.buffer.array(), this.buffer.position()))).createBufferedImage();
    }

    public String toString() {
        return "ImgWriterPPM: WxH = " + this.w + "x" + this.h + ", Components = " + this.cps[0] + "," + this.cps[1] + "," + this.cps[2] + "\nUnderlying RandomAccessFile:\n";
    }
}
