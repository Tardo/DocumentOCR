package jj2000.j2k.wavelet.synthesis;

public interface InvWTData extends MultiResImgData {
    int getCbULX();

    int getCbULY();

    SubbandSyn getSynSubbandTree(int i, int i2);
}
