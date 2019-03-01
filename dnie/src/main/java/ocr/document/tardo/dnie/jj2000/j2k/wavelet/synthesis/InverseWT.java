package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.BlkImgDataSrc;

public abstract class InverseWT extends InvWTAdapter implements BlkImgDataSrc {
    public InverseWT(MultiResImgData src, DecoderSpecs decSpec) {
        super(src, decSpec);
    }

    public static InverseWT createInstance(CBlkWTDataSrcDec src, DecoderSpecs decSpec) {
        return new InvWTFull(src, decSpec);
    }
}
