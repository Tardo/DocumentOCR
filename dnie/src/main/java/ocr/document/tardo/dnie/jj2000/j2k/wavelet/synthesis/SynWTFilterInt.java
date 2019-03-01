package jj2000.j2k.wavelet.synthesis;

public abstract class SynWTFilterInt extends SynWTFilter {
    public abstract void synthetize_hpf(int[] iArr, int i, int i2, int i3, int[] iArr2, int i4, int i5, int i6, int[] iArr3, int i7, int i8);

    public abstract void synthetize_lpf(int[] iArr, int i, int i2, int i3, int[] iArr2, int i4, int i5, int i6, int[] iArr3, int i7, int i8);

    public void synthetize_lpf(Object lowSig, int lowOff, int lowLen, int lowStep, Object highSig, int highOff, int highLen, int highStep, Object outSig, int outOff, int outStep) {
        synthetize_lpf((int[]) lowSig, lowOff, lowLen, lowStep, (int[]) highSig, highOff, highLen, highStep, (int[]) outSig, outOff, outStep);
    }

    public void synthetize_hpf(Object lowSig, int lowOff, int lowLen, int lowStep, Object highSig, int highOff, int highLen, int highStep, Object outSig, int outOff, int outStep) {
        synthetize_hpf((int[]) lowSig, lowOff, lowLen, lowStep, (int[]) highSig, highOff, highLen, highStep, (int[]) outSig, outOff, outStep);
    }

    public int getDataType() {
        return 3;
    }
}
