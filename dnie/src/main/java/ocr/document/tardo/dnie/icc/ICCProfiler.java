package icc;

import colorspace.ColorSpace;
import colorspace.ColorSpaceException;
import colorspace.ColorSpaceMapper;
import icc.lut.MatrixBasedTransformException;
import icc.lut.MatrixBasedTransformTosRGB;
import icc.lut.MonochromeTransformException;
import icc.lut.MonochromeTransformTosRGB;
import java.io.IOException;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.util.FacilityManager;

public class ICCProfiler extends ColorSpaceMapper {
    private static final int BLUE = 2;
    private static final int GRAY = 0;
    private static final int GREEN = 1;
    public static final char OPT_PREFIX = 'I';
    private static final int RED = 0;
    protected static final String eol = System.getProperty("line.separator");
    ICCProfile icc = null;
    private RestrictedICCProfile iccp = null;
    RestrictedICCProfile ricc = null;
    private DataBlkFloat[] tempFloat;
    private DataBlkInt[] tempInt;
    private Object xform = null;

    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ICCProfileException, ColorSpaceException {
        return new ICCProfiler(src, csMap);
    }

    protected ICCProfiler(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException, IOException, ICCProfileException, IllegalArgumentException {
        super(src, csMap);
        initialize();
        this.iccp = getICCProfile(csMap);
        if (this.ncomps == 1) {
            this.xform = new MonochromeTransformTosRGB(this.iccp, this.maxValueArray[0], this.shiftValueArray[0]);
        } else {
            this.xform = new MatrixBasedTransformTosRGB(this.iccp, this.maxValueArray, this.shiftValueArray);
        }
    }

    private void initialize() {
        this.tempInt = new DataBlkInt[this.ncomps];
        this.tempFloat = new DataBlkFloat[this.ncomps];
        for (int i = 0; i < this.ncomps; i++) {
            this.tempInt[i] = new DataBlkInt();
            this.tempFloat[i] = new DataBlkFloat();
        }
    }

    private RestrictedICCProfile getICCProfile(ColorSpace csm) throws ColorSpaceException, ICCProfileException, IllegalArgumentException {
        switch (this.ncomps) {
            case 1:
                this.icc = ICCMonochromeInputProfile.createInstance(csm);
                this.ricc = this.icc.parse();
                if (this.ricc.getType() != 0) {
                    throw new IllegalArgumentException("wrong ICCProfile type for image");
                }
                break;
            case 3:
                this.icc = ICCMatrixBasedInputProfile.createInstance(csm);
                this.ricc = this.icc.parse();
                if (this.ricc.getType() != 1) {
                    throw new IllegalArgumentException("wrong ICCProfile type for image");
                }
                break;
            default:
                throw new IllegalArgumentException("illegal number of components (" + this.ncomps + ") in image");
        }
        return this.ricc;
    }

    public DataBlk getCompData(DataBlk outblk, int c) {
        try {
            if (this.ncomps == 1 || this.ncomps == 3) {
                int type = outblk.getDataType();
                for (int i = 0; i < this.ncomps; i++) {
                    int fixedPtBits = this.src.getFixedPoint(i);
                    int shiftVal = this.shiftValueArray[i];
                    int maxVal = this.maxValueArray[i];
                    int row;
                    int leftedgeIn;
                    int rightedgeIn;
                    int leftedgeOut;
                    int rightedgeOut;
                    int kOut;
                    int kIn;
                    switch (type) {
                        case 3:
                            ColorSpaceMapper.copyGeometry(this.workInt[i], outblk);
                            ColorSpaceMapper.copyGeometry(this.tempInt[i], outblk);
                            ColorSpaceMapper.copyGeometry(this.inInt[i], outblk);
                            ColorSpaceMapper.setInternalBuffer(outblk);
                            this.workDataInt[i] = (int[]) this.workInt[i].getData();
                            this.inInt[i] = (DataBlkInt) this.src.getInternCompData(this.inInt[i], i);
                            this.dataInt[i] = this.inInt[i].getDataInt();
                            for (row = 0; row < outblk.f38h; row++) {
                                leftedgeIn = this.inInt[i].offset + (this.inInt[i].scanw * row);
                                rightedgeIn = leftedgeIn + this.inInt[i].w;
                                leftedgeOut = outblk.offset + (outblk.scanw * row);
                                rightedgeOut = leftedgeOut + outblk.f39w;
                                kOut = leftedgeOut;
                                kIn = leftedgeIn;
                                while (kIn < rightedgeIn) {
                                    int tmpInt = (this.dataInt[i][kIn] >> fixedPtBits) + shiftVal;
                                    int[] iArr = this.workDataInt[i];
                                    if (tmpInt < 0) {
                                        tmpInt = 0;
                                    } else if (tmpInt > maxVal) {
                                        tmpInt = maxVal;
                                    }
                                    iArr[kOut] = tmpInt;
                                    kIn++;
                                    kOut++;
                                }
                            }
                            break;
                        case 4:
                            ColorSpaceMapper.copyGeometry(this.workFloat[i], outblk);
                            ColorSpaceMapper.copyGeometry(this.tempFloat[i], outblk);
                            ColorSpaceMapper.copyGeometry(this.inFloat[i], outblk);
                            ColorSpaceMapper.setInternalBuffer(outblk);
                            this.workDataFloat[i] = (float[]) this.workFloat[i].getData();
                            this.inFloat[i] = (DataBlkFloat) this.src.getInternCompData(this.inFloat[i], i);
                            this.dataFloat[i] = this.inFloat[i].getDataFloat();
                            for (row = 0; row < outblk.f38h; row++) {
                                leftedgeIn = this.inFloat[i].offset + (this.inFloat[i].scanw * row);
                                rightedgeIn = leftedgeIn + this.inFloat[i].w;
                                leftedgeOut = outblk.offset + (outblk.scanw * row);
                                rightedgeOut = leftedgeOut + outblk.f39w;
                                kOut = leftedgeOut;
                                kIn = leftedgeIn;
                                while (kIn < rightedgeIn) {
                                    float tmpFloat = (this.dataFloat[i][kIn] / ((float) (1 << fixedPtBits))) + ((float) shiftVal);
                                    float[] fArr = this.workDataFloat[i];
                                    if (tmpFloat < 0.0f) {
                                        tmpFloat = 0.0f;
                                    } else if (tmpFloat > ((float) maxVal)) {
                                        tmpFloat = (float) maxVal;
                                    }
                                    fArr[kOut] = tmpFloat;
                                    kIn++;
                                    kOut++;
                                }
                            }
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid source datablock type");
                    }
                }
                switch (type) {
                    case 3:
                        if (this.ncomps == 1) {
                            ((MonochromeTransformTosRGB) this.xform).apply(this.workInt[c], this.tempInt[c]);
                        } else {
                            ((MatrixBasedTransformTosRGB) this.xform).apply(this.workInt, this.tempInt);
                        }
                        outblk.progressive = this.inInt[c].progressive;
                        outblk.setData(this.tempInt[c].getData());
                        break;
                    case 4:
                        if (this.ncomps == 1) {
                            ((MonochromeTransformTosRGB) this.xform).apply(this.workFloat[c], this.tempFloat[c]);
                        } else {
                            ((MatrixBasedTransformTosRGB) this.xform).apply(this.workFloat, this.tempFloat);
                        }
                        outblk.progressive = this.inFloat[c].progressive;
                        outblk.setData(this.tempFloat[c].getData());
                        break;
                    default:
                        throw new IllegalArgumentException("invalid source datablock type");
                }
                outblk.offset = 0;
                outblk.scanw = outblk.f39w;
                return outblk;
            }
            FacilityManager.getMsgLogger().printmsg(2, "ICCProfiler: icc profile _not_ applied to " + this.ncomps + " component image");
            return this.src.getCompData(outblk, c);
        } catch (MatrixBasedTransformException e) {
            FacilityManager.getMsgLogger().printmsg(3, "matrix transform problem:\n" + e.getMessage());
            if (this.pl.getParameter("debug").equals("on")) {
                e.printStackTrace();
            } else {
                FacilityManager.getMsgLogger().printmsg(3, "Use '-debug' option for more details");
            }
            return null;
        } catch (MonochromeTransformException e2) {
            FacilityManager.getMsgLogger().printmsg(3, "monochrome transform problem:\n" + e2.getMessage());
            if (this.pl.getParameter("debug").equals("on")) {
                e2.printStackTrace();
            } else {
                FacilityManager.getMsgLogger().printmsg(3, "Use '-debug' option for more details");
            }
            return null;
        }
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return getCompData(out, c);
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[ICCProfiler:");
        StringBuffer body = new StringBuffer();
        if (this.icc != null) {
            body.append(eol).append(ColorSpace.indent("  ", this.icc.toString()));
        }
        if (this.xform != null) {
            body.append(eol).append(ColorSpace.indent("  ", this.xform.toString()));
        }
        rep.append(ColorSpace.indent("  ", body));
        return rep.append("]").toString();
    }
}
