package jj2000.j2k.wavelet;

import jj2000.j2k.image.ImgData;

public interface WaveletTransform extends ImgData {
    public static final int WT_IMPL_FULL = 2;
    public static final int WT_IMPL_LINE = 0;

    int getImplementationType(int i);

    boolean isReversible(int i, int i2);
}
