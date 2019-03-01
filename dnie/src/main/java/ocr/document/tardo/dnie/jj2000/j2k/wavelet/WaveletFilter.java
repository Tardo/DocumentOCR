package jj2000.j2k.wavelet;

public interface WaveletFilter {
    public static final int WT_FILTER_FLOAT_CONVOL = 2;
    public static final int WT_FILTER_FLOAT_LIFT = 1;
    public static final int WT_FILTER_INT_LIFT = 0;

    int getAnHighNegSupport();

    int getAnHighPosSupport();

    int getAnLowNegSupport();

    int getAnLowPosSupport();

    int getDataType();

    int getImplType();

    int getSynHighNegSupport();

    int getSynHighPosSupport();

    int getSynLowNegSupport();

    int getSynLowPosSupport();

    boolean isReversible();

    boolean isSameAsFullWT(int i, int i2, int i3);
}
