package jj2000.j2k.image;

public class ImgDataConverter extends ImgDataAdapter implements BlkImgDataSrc {
    private int fp;
    private BlkImgDataSrc src;
    private DataBlk srcBlk = new DataBlkInt();

    public ImgDataConverter(BlkImgDataSrc imgSrc, int fp) {
        super(imgSrc);
        this.src = imgSrc;
        this.fp = fp;
    }

    public ImgDataConverter(BlkImgDataSrc imgSrc) {
        super(imgSrc);
        this.src = imgSrc;
        this.fp = 0;
    }

    public int getFixedPoint(int c) {
        return this.fp;
    }

    public DataBlk getCompData(DataBlk blk, int c) {
        return getData(blk, c, false);
    }

    public final DataBlk getInternCompData(DataBlk blk, int c) {
        return getData(blk, c, true);
    }

    private DataBlk getData(DataBlk blk, int c, boolean intern) {
        DataBlk reqBlk;
        int otype = blk.getDataType();
        if (otype == this.srcBlk.getDataType()) {
            reqBlk = blk;
        } else {
            reqBlk = this.srcBlk;
            reqBlk.ulx = blk.ulx;
            reqBlk.uly = blk.uly;
            reqBlk.f39w = blk.f39w;
            reqBlk.f38h = blk.f38h;
        }
        if (intern) {
            this.srcBlk = this.src.getInternCompData(reqBlk, c);
        } else {
            this.srcBlk = this.src.getCompData(reqBlk, c);
        }
        if (this.srcBlk.getDataType() == otype) {
            return this.srcBlk;
        }
        int w = this.srcBlk.f39w;
        int h = this.srcBlk.f38h;
        float mult;
        int k;
        int kSrc;
        int i;
        int kmin;
        switch (otype) {
            case 3:
                int[] iarr = (int[]) blk.getData();
                if (iarr == null || iarr.length < w * h) {
                    iarr = new int[(w * h)];
                    blk.setData(iarr);
                }
                blk.scanw = this.srcBlk.f39w;
                blk.offset = 0;
                blk.progressive = this.srcBlk.progressive;
                float[] srcFArr = (float[]) this.srcBlk.getData();
                if (this.fp != 0) {
                    mult = (float) (1 << this.fp);
                    k = (w * h) - 1;
                    kSrc = ((this.srcBlk.offset + ((h - 1) * this.srcBlk.scanw)) + w) - 1;
                    for (i = h - 1; i >= 0; i--) {
                        kmin = k - w;
                        while (k > kmin) {
                            if (srcFArr[kSrc] > 0.0f) {
                                iarr[k] = (int) ((srcFArr[kSrc] * mult) + 0.5f);
                            } else {
                                iarr[k] = (int) ((srcFArr[kSrc] * mult) - 0.5f);
                            }
                            k--;
                            kSrc--;
                        }
                        kSrc -= this.srcBlk.scanw - w;
                    }
                    return blk;
                }
                k = (w * h) - 1;
                kSrc = ((this.srcBlk.offset + ((h - 1) * this.srcBlk.scanw)) + w) - 1;
                for (i = h - 1; i >= 0; i--) {
                    kmin = k - w;
                    while (k > kmin) {
                        if (srcFArr[kSrc] > 0.0f) {
                            iarr[k] = (int) (srcFArr[kSrc] + 0.5f);
                        } else {
                            iarr[k] = (int) (srcFArr[kSrc] - 0.5f);
                        }
                        k--;
                        kSrc--;
                    }
                    kSrc -= this.srcBlk.scanw - w;
                }
                return blk;
            case 4:
                float[] farr = (float[]) blk.getData();
                if (farr == null || farr.length < w * h) {
                    farr = new float[(w * h)];
                    blk.setData(farr);
                }
                blk.scanw = this.srcBlk.f39w;
                blk.offset = 0;
                blk.progressive = this.srcBlk.progressive;
                int[] srcIArr = (int[]) this.srcBlk.getData();
                this.fp = this.src.getFixedPoint(c);
                if (this.fp != 0) {
                    mult = 1.0f / ((float) (1 << this.fp));
                    k = (w * h) - 1;
                    kSrc = ((this.srcBlk.offset + ((h - 1) * this.srcBlk.scanw)) + w) - 1;
                    for (i = h - 1; i >= 0; i--) {
                        kmin = k - w;
                        while (k > kmin) {
                            farr[k] = ((float) srcIArr[kSrc]) * mult;
                            k--;
                            kSrc--;
                        }
                        kSrc -= this.srcBlk.scanw - w;
                    }
                    return blk;
                }
                k = (w * h) - 1;
                kSrc = ((this.srcBlk.offset + ((h - 1) * this.srcBlk.scanw)) + w) - 1;
                for (i = h - 1; i >= 0; i--) {
                    kmin = k - w;
                    while (k > kmin) {
                        farr[k] = (float) srcIArr[kSrc];
                        k--;
                        kSrc--;
                    }
                    kSrc -= this.srcBlk.scanw - w;
                }
                return blk;
            default:
                throw new IllegalArgumentException("Only integer and float data are supported by JJ2000");
        }
    }
}
