package jj2000.j2k.wavelet.synthesis;

public abstract class SynWTFilterFloat extends SynWTFilter {
    public abstract void synthetize_hpf(float[] fArr, int i, int i2, int i3, float[] fArr2, int i4, int i5, int i6, float[] fArr3, int i7, int i8);

    public abstract void synthetize_lpf(float[] fArr, int i, int i2, int i3, float[] fArr2, int i4, int i5, int i6, float[] fArr3, int i7, int i8);

    public void synthetize_lpf(Object lowSig, int lowOff, int lowLen, int lowStep, Object highSig, int highOff, int highLen, int highStep, Object outSig, int outOff, int outStep) {
        synthetize_lpf((float[]) lowSig, lowOff, lowLen, lowStep, (float[]) highSig, highOff, highLen, highStep, (float[]) outSig, outOff, outStep);
    }

    public void synthetize_hpf(Object lowSig, int lowOff, int lowLen, int lowStep, Object highSig, int highOff, int highLen, int highStep, Object outSig, int outOff, int outStep) {
        synthetize_hpf((float[]) lowSig, lowOff, lowLen, lowStep, (float[]) highSig, highOff, highLen, highStep, (float[]) outSig, outOff, outStep);
    }

    public int getDataType() {
        return 4;
    }
}
