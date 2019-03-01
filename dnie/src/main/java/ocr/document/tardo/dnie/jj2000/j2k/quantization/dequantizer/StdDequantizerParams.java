package jj2000.j2k.quantization.dequantizer;

public class StdDequantizerParams extends DequantizerParams {
    public int[][] exp;
    public float[][] nStep;

    public int getDequantizerType() {
        return 0;
    }
}
