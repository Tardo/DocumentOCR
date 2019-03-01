package jj2000.j2k.entropy.decoder;

import jj2000.j2k.wavelet.synthesis.InvWTData;
import jj2000.j2k.wavelet.synthesis.SubbandSyn;

public interface CodedCBlkDataSrcDec extends InvWTData {
    DecLyrdCBlk getCodeBlock(int i, int i2, int i3, SubbandSyn subbandSyn, int i4, int i5, DecLyrdCBlk decLyrdCBlk);
}
