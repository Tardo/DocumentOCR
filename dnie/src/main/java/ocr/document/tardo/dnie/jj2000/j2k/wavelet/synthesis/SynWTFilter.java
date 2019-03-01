package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.codestream.Markers;
import jj2000.j2k.wavelet.WaveletFilter;

public abstract class SynWTFilter implements WaveletFilter, Markers {
    public abstract void synthetize_hpf(Object obj, int i, int i2, int i3, Object obj2, int i4, int i5, int i6, Object obj3, int i7, int i8);

    public abstract void synthetize_lpf(Object obj, int i, int i2, int i3, Object obj2, int i4, int i5, int i6, Object obj3, int i7, int i8);
}
