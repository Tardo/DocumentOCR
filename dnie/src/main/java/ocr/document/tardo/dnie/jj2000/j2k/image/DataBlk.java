package jj2000.j2k.image;

public abstract class DataBlk {
    public static final int TYPE_BYTE = 0;
    public static final int TYPE_FLOAT = 4;
    public static final int TYPE_INT = 3;
    public static final int TYPE_SHORT = 1;
    /* renamed from: h */
    public int f38h;
    public int offset;
    public boolean progressive;
    public int scanw;
    public int ulx;
    public int uly;
    /* renamed from: w */
    public int f39w;

    public abstract Object getData();

    public abstract int getDataType();

    public abstract void setData(Object obj);

    public static int getSize(int type) {
        switch (type) {
            case 0:
                return 8;
            case 1:
                return 16;
            case 3:
            case 4:
                return 32;
            default:
                throw new IllegalArgumentException();
        }
    }

    public String toString() {
        String typeString = "";
        switch (getDataType()) {
            case 0:
                typeString = "Unsigned Byte";
                break;
            case 1:
                typeString = "Short";
                break;
            case 3:
                typeString = "Integer";
                break;
            case 4:
                typeString = "Float";
                break;
        }
        return "DataBlk: upper-left(" + this.ulx + "," + this.uly + "), width=" + this.f39w + ", height=" + this.f38h + ", progressive=" + this.progressive + ", offset=" + this.offset + ", scanw=" + this.scanw + ", type=" + typeString;
    }
}
