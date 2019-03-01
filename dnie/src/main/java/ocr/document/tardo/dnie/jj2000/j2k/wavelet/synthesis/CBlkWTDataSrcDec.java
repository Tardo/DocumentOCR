package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.image.DataBlk;

public interface CBlkWTDataSrcDec extends InvWTData {
    DataBlk getCodeBlock(int i, int i2, int i3, SubbandSyn subbandSyn, DataBlk dataBlk);

    int getFixedPoint(int i);

    DataBlk getInternCodeBlock(int i, int i2, int i3, SubbandSyn subbandSyn, DataBlk dataBlk);

    int getNomRangeBits(int i);
}
