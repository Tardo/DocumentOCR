package jj2000.j2k.wavelet;

public abstract class WTFilterSpec {
    public static final byte FILTER_SPEC_COMP_DEF = (byte) 1;
    public static final byte FILTER_SPEC_MAIN_DEF = (byte) 0;
    public static final byte FILTER_SPEC_TILE_COMP = (byte) 3;
    public static final byte FILTER_SPEC_TILE_DEF = (byte) 2;
    protected byte[] specValType;

    public abstract int getWTDataType();

    protected WTFilterSpec(int nc) {
        this.specValType = new byte[nc];
    }

    public byte getKerSpecType(int n) {
        return this.specValType[n];
    }
}
