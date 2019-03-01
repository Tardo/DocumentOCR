package jj2000.j2k.wavelet.synthesis;

public class SynWTFilterIntLift5x3 extends SynWTFilterInt {
    public void synthetize_lpf(int[] lowSig, int lowOff, int lowLen, int lowStep, int[] highSig, int highOff, int highLen, int highStep, int[] outSig, int outOff, int outStep) {
        int i;
        int outLen = lowLen + highLen;
        int iStep = outStep * 2;
        int lk = lowOff;
        int hk = highOff;
        int ik = outOff;
        if (outLen > 1) {
            outSig[ik] = lowSig[lk] - ((highSig[hk] + 1) >> 1);
        } else {
            outSig[ik] = lowSig[lk];
        }
        lk += lowStep;
        hk += highStep;
        ik += iStep;
        for (i = 2; i < outLen - 1; i += 2) {
            outSig[ik] = lowSig[lk] - (((highSig[hk - highStep] + highSig[hk]) + 2) >> 2);
            lk += lowStep;
            hk += highStep;
            ik += iStep;
        }
        if (outLen % 2 == 1 && outLen > 2) {
            outSig[ik] = lowSig[lk] - (((highSig[hk - highStep] * 2) + 2) >> 2);
        }
        hk = highOff;
        ik = outOff + outStep;
        for (i = 1; i < outLen - 1; i += 2) {
            outSig[ik] = highSig[hk] + ((outSig[ik - outStep] + outSig[ik + outStep]) >> 1);
            hk += highStep;
            ik += iStep;
        }
        if (outLen % 2 == 0 && outLen > 1) {
            outSig[ik] = highSig[hk] + outSig[ik - outStep];
        }
    }

    public void synthetize_hpf(int[] lowSig, int lowOff, int lowLen, int lowStep, int[] highSig, int highOff, int highLen, int highStep, int[] outSig, int outOff, int outStep) {
        int i;
        int outLen = lowLen + highLen;
        int iStep = outStep * 2;
        int lk = lowOff;
        int hk = highOff;
        int ik = outOff + outStep;
        for (i = 1; i < outLen - 1; i += 2) {
            outSig[ik] = lowSig[lk] - (((highSig[hk] + highSig[hk + highStep]) + 2) >> 2);
            lk += lowStep;
            hk += highStep;
            ik += iStep;
        }
        if (outLen > 1 && outLen % 2 == 0) {
            outSig[ik] = lowSig[lk] - (((highSig[hk] * 2) + 2) >> 2);
        }
        hk = highOff;
        ik = outOff;
        if (outLen > 1) {
            outSig[ik] = highSig[hk] + outSig[ik + outStep];
        } else {
            outSig[ik] = highSig[hk] >> 1;
        }
        hk += highStep;
        ik += iStep;
        for (i = 2; i < outLen - 1; i += 2) {
            outSig[ik] = highSig[hk] + ((outSig[ik - outStep] + outSig[ik + outStep]) >> 1);
            hk += highStep;
            ik += iStep;
        }
        if (outLen % 2 == 1 && outLen > 1) {
            outSig[ik] = highSig[hk] + outSig[ik - outStep];
        }
    }

    public int getAnLowNegSupport() {
        return 2;
    }

    public int getAnLowPosSupport() {
        return 2;
    }

    public int getAnHighNegSupport() {
        return 1;
    }

    public int getAnHighPosSupport() {
        return 1;
    }

    public int getSynLowNegSupport() {
        return 1;
    }

    public int getSynLowPosSupport() {
        return 1;
    }

    public int getSynHighNegSupport() {
        return 2;
    }

    public int getSynHighPosSupport() {
        return 2;
    }

    public int getImplType() {
        return 0;
    }

    public boolean isReversible() {
        return true;
    }

    public boolean isSameAsFullWT(int tailOvrlp, int headOvrlp, int inLen) {
        if (inLen % 2 == 0) {
            if (tailOvrlp < 2 || headOvrlp < 1) {
                return false;
            }
            return true;
        } else if (tailOvrlp < 2 || headOvrlp < 2) {
            return false;
        } else {
            return true;
        }
    }

    public String toString() {
        return "w5x3 (lifting)";
    }
}
