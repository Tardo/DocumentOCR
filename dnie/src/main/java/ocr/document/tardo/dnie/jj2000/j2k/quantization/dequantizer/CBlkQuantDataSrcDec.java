package jj2000.j2k.quantization.dequantizer;

import jj2000.j2k.image.DataBlk;
import jj2000.j2k.wavelet.synthesis.InvWTData;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public interface CBlkQuantDataSrcDec extends InvWTData {
    DataBlk getCodeBlock(int i, int i2, int i3, SubbandSyn subbandSyn, DataBlk dataBlk);

    DataBlk getInternCodeBlock(int i, int i2, int i3, SubbandSyn subbandSyn, DataBlk dataBlk);
}
