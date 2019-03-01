package jj2000.j2k.image;

public class DataBlkInt extends DataBlk {
    public int[] data;

    public DataBlkInt(int ulx, int uly, int w, int h) {
        this.ulx = ulx;
        this.uly = uly;
        this.w = w;
        this.h = h;
        this.offset = 0;
        this.scanw = w;
        this.data = new int[(w * h)];
    }

    public DataBlkInt(DataBlkInt src) {
        this.ulx = src.ulx;
        this.uly = src.uly;
        this.w = src.w;
        this.h = src.h;
        this.offset = 0;
        this.scanw = this.w;
        this.data = new int[(this.w * this.h)];
        for (int i = 0; i < this.h; i++) {
            System.arraycopy(src.data, src.scanw * i, this.data, this.scanw * i, this.w);
        }
    }

    public final int getDataType() {
        return 3;
    }

    public final Object getData() {
        return this.data;
    }

    public final int[] getDataInt() {
        return this.data;
    }

    public final void setData(Object arr) {
        this.data = (int[]) arr;
    }

    public final void setDataInt(int[] arr) {
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
