package jj2000.j2k.image;

public class DataBlkFloat extends DataBlk {
    public float[] data;

    public DataBlkFloat(int ulx, int uly, int w, int h) {
        this.ulx = ulx;
        this.uly = uly;
        this.w = w;
        this.h = h;
        this.offset = 0;
        this.scanw = w;
        this.data = new float[(w * h)];
    }

    public DataBlkFloat(DataBlkFloat src) {
        this.ulx = src.ulx;
        this.uly = src.uly;
        this.w = src.w;
        this.h = src.h;
        this.offset = 0;
        this.scanw = this.w;
        this.data = new float[(this.w * this.h)];
        for (int i = 0; i < this.h; i++) {
            System.arraycopy(src.data, src.scanw * i, this.data, this.scanw * i, this.w);
        }
    }

    public final int getDataType() {
        return 4;
    }

    public final Object getData() {
        return this.data;
    }

    public final float[] getDataFloat() {
        return this.data;
    }

    public final void setData(Object arr) {
        this.data = (float[]) arr;
    }

    public final void setDataFloat(float[] arr) {
        this.data = arr;
    }

    public String toString() {
        String str = super.toString();
        if (this.data != null) {
            return str + ",data=" + this.data.length + " bytes";
        }
        return str;
    }
}
