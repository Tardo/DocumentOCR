package colorspace;

import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;

public class Resampler extends ColorSpaceMapper {
    final int hspan = 0;
    private final int maxCompSubsX;
    private final int maxCompSubsY;
    private final int minCompSubsX;
    private final int minCompSubsY;
    final int wspan = 0;

    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        return new Resampler(src, csMap);
    }

    protected Resampler(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src, csMap);
        int minX = src.getCompSubsX(0);
        int minY = src.getCompSubsY(0);
        int maxX = minX;
        int maxY = minY;
        for (int c = 1; c < this.ncomps; c++) {
            minX = Math.min(minX, src.getCompSubsX(c));
            minY = Math.min(minY, src.getCompSubsY(c));
            maxX = Math.max(maxX, src.getCompSubsX(c));
            maxY = Math.max(maxY, src.getCompSubsY(c));
        }
        if ((maxX == 1 || maxX == 2) && (maxY == 1 || maxY == 2)) {
            this.minCompSubsX = minX;
            this.minCompSubsY = minY;
            this.maxCompSubsX = maxX;
            this.maxCompSubsY = maxY;
            return;
        }
        throw new ColorSpaceException("Upsampling by other than 2:1 not supported");
    }

    public DataBlk getInternCompData(DataBlk outblk, int c) {
        if (this.src.getCompSubsX(c) == 1 && this.src.getCompSubsY(c) == 1) {
            return this.src.getInternCompData(outblk, c);
        }
        int wfactor = this.src.getCompSubsX(c);
        int hfactor = this.src.getCompSubsY(c);
        if ((wfactor == 2 || wfactor == 1) && (hfactor == 2 || hfactor == 1)) {
            int y0Out = outblk.uly;
            int y1Out = (outblk.f38h + y0Out) - 1;
            int x0Out = outblk.ulx;
            int x1Out = (outblk.f39w + x0Out) - 1;
            int y0In = y0Out / hfactor;
            int x0In = x0Out / wfactor;
            int reqW = ((x1Out / wfactor) - x0In) + 1;
            int reqH = ((y1Out / hfactor) - y0In) + 1;
            int yOut;
            int leftedgeIn;
            int rightedgeIn;
            int leftedgeOut;
            int rightedgeOut;
            int kIn;
            int kOut;
            int kOut2;
            int kIn2;
            switch (outblk.getDataType()) {
                case 3:
                    DataBlkInt inblkInt = (DataBlkInt) this.src.getInternCompData(new DataBlkInt(x0In, y0In, reqW, reqH), c);
                    this.dataInt[c] = inblkInt.getDataInt();
                    int[] outdataInt = (int[]) outblk.getData();
                    if (outdataInt == null || outdataInt.length != outblk.f39w * outblk.f38h) {
                        outdataInt = new int[(outblk.f38h * outblk.f39w)];
                        outblk.setData(outdataInt);
                    }
                    yOut = y0Out;
                    while (yOut <= y1Out) {
                        leftedgeIn = inblkInt.offset + (((yOut / hfactor) - y0In) * inblkInt.scanw);
                        rightedgeIn = leftedgeIn + inblkInt.w;
                        leftedgeOut = outblk.offset + ((yOut - y0Out) * outblk.scanw);
                        rightedgeOut = leftedgeOut + outblk.f39w;
                        kIn = leftedgeIn;
                        kOut = leftedgeOut;
                        if ((x0Out & 1) == 1) {
                            kOut2 = kOut + 1;
                            kIn2 = kIn + 1;
                            outdataInt[kOut] = this.dataInt[c][kIn];
                            kIn = kIn2;
                            kOut = kOut2;
                        }
                        if ((x1Out & 1) == 0) {
                            rightedgeOut--;
                            kIn2 = kIn;
                            kOut2 = kOut;
                        } else {
                            kIn2 = kIn;
                            kOut2 = kOut;
                        }
                        while (kOut2 < rightedgeOut) {
                            kOut = kOut2 + 1;
                            outdataInt[kOut2] = this.dataInt[c][kIn2];
                            kOut2 = kOut + 1;
                            kIn = kIn2 + 1;
                            outdataInt[kOut] = this.dataInt[c][kIn2];
                            kIn2 = kIn;
                        }
                        if ((x1Out & 1) == 0) {
                            kOut = kOut2 + 1;
                            outdataInt[kOut2] = this.dataInt[c][kIn2];
                        } else {
                            kOut = kOut2;
                        }
                        yOut++;
                        kIn = kIn2;
                    }
                    outblk.progressive = inblkInt.progressive;
                    return outblk;
                case 4:
                    DataBlkFloat inblkFloat = (DataBlkFloat) this.src.getInternCompData(new DataBlkFloat(x0In, y0In, reqW, reqH), c);
                    this.dataFloat[c] = inblkFloat.getDataFloat();
                    float[] outdataFloat = (float[]) outblk.getData();
                    if (outdataFloat == null || outdataFloat.length != outblk.f39w * outblk.f38h) {
                        outdataFloat = new float[(outblk.f38h * outblk.f39w)];
                        outblk.setData(outdataFloat);
                    }
                    yOut = y0Out;
                    while (yOut <= y1Out) {
                        leftedgeIn = inblkFloat.offset + (((yOut / hfactor) - y0In) * inblkFloat.scanw);
                        rightedgeIn = leftedgeIn + inblkFloat.w;
                        leftedgeOut = outblk.offset + ((yOut - y0Out) * outblk.scanw);
                        rightedgeOut = leftedgeOut + outblk.f39w;
                        kIn = leftedgeIn;
                        kOut = leftedgeOut;
                        if ((x0Out & 1) == 1) {
                            kOut2 = kOut + 1;
                            kIn2 = kIn + 1;
                            outdataFloat[kOut] = this.dataFloat[c][kIn];
                            kIn = kIn2;
                            kOut = kOut2;
                        }
                        if ((x1Out & 1) == 0) {
                            rightedgeOut--;
                            kIn2 = kIn;
                            kOut2 = kOut;
                        } else {
                            kIn2 = kIn;
                            kOut2 = kOut;
                        }
                        while (kOut2 < rightedgeOut) {
                            kOut = kOut2 + 1;
                            outdataFloat[kOut2] = this.dataFloat[c][kIn2];
                            kOut2 = kOut + 1;
                            kIn = kIn2 + 1;
                            outdataFloat[kOut] = this.dataFloat[c][kIn2];
                            kIn2 = kIn;
                        }
                        if ((x1Out & 1) == 0) {
                            kOut = kOut2 + 1;
                            outdataFloat[kOut2] = this.dataFloat[c][kIn2];
                        }
                        yOut++;
                        kIn = kIn2;
                    }
                    outblk.progressive = inblkFloat.progressive;
                    return outblk;
                default:
                    throw new IllegalArgumentException("invalid source datablock type");
            }
        }
        throw new IllegalArgumentException("Upsampling by other than 2:1 not supported");
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[Resampler: ncomps= " + this.ncomps);
        StringBuffer body = new StringBuffer("  ");
        for (int i = 0; i < this.ncomps; i++) {
            body.append(eol);
            body.append("comp[");
            body.append(i);
            body.append("] xscale= ");
            body.append(this.imgdatasrc.getCompSubsX(i));
            body.append(", yscale= ");
            body.append(this.imgdatasrc.getCompSubsY(i));
        }
        rep.append(ColorSpace.indent("  ", body));
        return rep.append("]").toString();
    }

    public DataBlk getCompData(DataBlk outblk, int c) {
        return getInternCompData(outblk, c);
    }

    public int getCompImgHeight(int c) {
        return this.src.getCompImgHeight(c) * this.src.getCompSubsY(c);
    }

    public int getCompImgWidth(int c) {
        return this.src.getCompImgWidth(c) * this.src.getCompSubsX(c);
    }

    public int getCompSubsX(int c) {
        return 1;
    }

    public int getCompSubsY(int c) {
        return 1;
    }

    public int getTileCompHeight(int t, int c) {
        return this.src.getTileCompHeight(t, c) * this.src.getCompSubsY(c);
    }

    public int getTileCompWidth(int t, int c) {
        return this.src.getTileCompWidth(t, c) * this.src.getCompSubsX(c);
    }
}
