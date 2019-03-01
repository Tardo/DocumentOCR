package jj2000.j2k.entropy.decoder;

import jj2000.j2k.quantization.dequantizer.CBlkQuantDataSrcDec;
import jj2000.j2k.wavelet.synthesis.MultiResImgDataAdapter;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public abstract class EntropyDecoder extends MultiResImgDataAdapter implements CBlkQuantDataSrcDec {
    public static final char OPT_PREFIX = 'C';
    private static final String[][] pinfo;
    protected CodedCBlkDataSrcDec src;

    static {
        r0 = new String[2][];
        r0[0] = new String[]{"Cverber", "[on|off]", "Specifies if the entropy decoder should be verbose about detected errors. If 'on' a message is printed whenever an error is detected.", "on"};
        r0[1] = new String[]{"Cer", "[on|off]", "Specifies if error detection should be performed by the entropy decoder engine. If errors are detected they will be concealed and the resulting distortion will be less important. Note that errors can only be detected if the encoder that generated the data included error resilience information.", "on"};
        pinfo = r0;
    }

    public EntropyDecoder(CodedCBlkDataSrcDec src) {
        super(src);
        this.src = src;
    }

    public SubbandSyn getSynSubbandTree(int t, int c) {
        return this.src.getSynSubbandTree(t, c);
    }

    public int getCbULX() {
        return this.src.getCbULX();
    }

    public int getCbULY() {
        return this.src.getCbULY();
    }

    public static String[][] getParameterInfo() {
        return pinfo;
    }
}
