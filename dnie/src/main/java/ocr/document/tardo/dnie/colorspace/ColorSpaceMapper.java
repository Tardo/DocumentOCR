package colorspace;

import colorspace.ColorSpace.CSEnum;
import icc.ICCProfileException;
import icc.ICCProfiler;
import java.io.IOException;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.DataBlk;
import jj2000.j2k.image.DataBlkFloat;
import jj2000.j2k.image.DataBlkInt;
import jj2000.j2k.image.ImgDataAdapter;
import jj2000.j2k.util.ParameterList;

public abstract class ColorSpaceMapper extends ImgDataAdapter implements BlkImgDataSrc {
    public static final char OPT_PREFIX = 'I';
    protected static final String eol = System.getProperty("line.separator");
    private static final String[][] pinfo;
    protected ComputedComponents computed = new ComputedComponents();
    protected ColorSpace csMap = null;
    protected float[][] dataFloat;
    protected int[][] dataInt;
    protected int[] fixedPtBitsArray = null;
    protected DataBlkFloat[] inFloat;
    protected DataBlkInt[] inInt;
    protected int[] maxValueArray = null;
    protected int ncomps = 0;
    protected ParameterList pl = null;
    protected int[] shiftValueArray = null;
    protected BlkImgDataSrc src = null;
    protected DataBlk[] srcBlk = null;
    protected float[][] workDataFloat;
    protected int[][] workDataInt;
    protected DataBlkFloat[] workFloat;
    protected DataBlkInt[] workInt;

    protected class ComputedComponents {
        /* renamed from: h */
        private int f0h = -1;
        private int offset = -1;
        private int scanw = -1;
        private int tIdx = -1;
        private int ulx = -1;
        private int uly = -1;
        /* renamed from: w */
        private int f1w = -1;

        public ComputedComponents() {
            clear();
        }

        public ComputedComponents(DataBlk db) {
            set(db);
        }

        public void set(DataBlk db) {
            this.f0h = db.f38h;
            this.f1w = db.f39w;
            this.ulx = db.ulx;
            this.uly = db.uly;
            this.offset = db.offset;
            this.scanw = db.scanw;
        }

        public void clear() {
            this.scanw = -1;
            this.offset = -1;
            this.uly = -1;
            this.ulx = -1;
            this.f1w = -1;
            this.f0h = -1;
        }

        public boolean equals(ComputedComponents cc) {
            return this.f0h == cc.f0h && this.f1w == cc.f1w && this.ulx == cc.ulx && this.uly == cc.uly && this.offset == cc.offset && this.scanw == cc.scanw;
        }
    }

    static {
        String[][] strArr = new String[1][];
        strArr[0] = new String[]{"IcolorSpacedebug", null, "Print debugging messages during colorspace mapping.", "off"};
        pinfo = strArr;
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }

    protected static void setInternalBuffer(DataBlk db) {
        switch (db.getDataType()) {
            case 3:
                if (db.getData() == null || ((int[]) db.getData()).length < db.f39w * db.f38h) {
                    db.setData(new int[(db.f39w * db.f38h)]);
                    return;
                }
                return;
            case 4:
                if (db.getData() == null || ((float[]) db.getData()).length < db.f39w * db.f38h) {
                    db.setData(new float[(db.f39w * db.f38h)]);
                    return;
                }
                return;
            default:
                throw new IllegalArgumentException("Invalid output datablock type");
        }
    }

    protected static void copyGeometry(DataBlk tgt, DataBlk src) {
        tgt.offset = 0;
        tgt.f38h = src.f38h;
        tgt.f39w = src.f39w;
        tgt.ulx = src.ulx;
        tgt.uly = src.uly;
        tgt.scanw = src.f39w;
        setInternalBuffer(tgt);
    }

    public static BlkImgDataSrc createInstance(BlkImgDataSrc src, ColorSpace csMap) throws IOException, ColorSpaceException, ICCProfileException {
        ParameterList parameterList = csMap.pl;
        ParameterList parameterList2 = csMap.pl;
        parameterList.checkList('I', ParameterList.toNameArray(pinfo));
        if (csMap.getMethod() == ColorSpace.ICC_PROFILED) {
            return ICCProfiler.createInstance(src, csMap);
        }
        CSEnum colorspace = csMap.getColorSpace();
        if (colorspace == ColorSpace.sRGB) {
            return EnumeratedColorSpaceMapper.createInstance(src, csMap);
        }
        if (colorspace == ColorSpace.GreyScale) {
            return EnumeratedColorSpaceMapper.createInstance(src, csMap);
        }
        if (colorspace == ColorSpace.sYCC) {
            return SYccColorSpaceMapper.createInstance(src, csMap);
        }
        if (colorspace == ColorSpace.Unknown) {
            return null;
        }
        throw new ColorSpaceException("Bad color space specification in image");
    }

    protected ColorSpaceMapper(BlkImgDataSrc src, ColorSpace csMap) throws ColorSpaceException {
        super(src);
        this.src = src;
        this.csMap = csMap;
        initialize();
    }

    private void initialize() throws ColorSpaceException {
        this.pl = this.csMap.pl;
        this.ncomps = this.src.getNumComps();
        this.shiftValueArray = new int[this.ncomps];
        this.maxValueArray = new int[this.ncomps];
        this.fixedPtBitsArray = new int[this.ncomps];
        this.srcBlk = new DataBlk[this.ncomps];
        this.inInt = new DataBlkInt[this.ncomps];
        this.inFloat = new DataBlkFloat[this.ncomps];
        this.workInt = new DataBlkInt[this.ncomps];
        this.workFloat = new DataBlkFloat[this.ncomps];
        this.dataInt = new int[this.ncomps][];
        this.dataFloat = new float[this.ncomps][];
        this.workDataInt = new int[this.ncomps][];
        this.workDataFloat = new float[this.ncomps][];
        this.dataInt = new int[this.ncomps][];
        this.dataFloat = new float[this.ncomps][];
        for (int i = 0; i < this.ncomps; i++) {
            this.shiftValueArray[i] = 1 << (this.src.getNomRangeBits(i) - 1);
            this.maxValueArray[i] = (1 << this.src.getNomRangeBits(i)) - 1;
            this.fixedPtBitsArray[i] = this.src.getFixedPoint(i);
            this.inInt[i] = new DataBlkInt();
            this.inFloat[i] = new DataBlkFloat();
            this.workInt[i] = new DataBlkInt();
            this.workInt[i].progressive = this.inInt[i].progressive;
            this.workFloat[i] = new DataBlkFloat();
            this.workFloat[i].progressive = this.inFloat[i].progressive;
        }
    }

    public int getFixedPoint(int c) {
        return this.src.getFixedPoint(c);
    }

    public DataBlk getCompData(DataBlk out, int c) {
        return this.src.getCompData(out, c);
    }

    public DataBlk getInternCompData(DataBlk out, int c) {
        return this.src.getInternCompData(out, c);
    }
}
