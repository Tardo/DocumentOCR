package jj2000.j2k.wavelet.synthesis;

public class SynWTFilterFloatLift9x7 extends SynWTFilterFloat {
    public static final float ALPHA = -1.5861343f;
    public static final float BETA = -0.052980117f;
    public static final float DELTA = 0.44350687f;
    public static final float GAMMA = 0.8829111f;
    public static final float KH = 1.2301741f;
    public static final float KL = 0.8128931f;

    public void synthetize_lpf(float[] lowSig, int lowOff, int lowLen, int lowStep, float[] highSig, int highOff, int highLen, int highStep, float[] outSig, int outOff, int outStep) {
        int outLen = lowLen + highLen;
        int iStep = outStep * 2;
        int lk = lowOff;
        int hk = highOff;
        int ik = outOff;
        if (outLen > 1) {
            outSig[ik] = (lowSig[lk] / 0.8128931f) - ((0.88701373f * highSig[hk]) / 1.2301741f);
        } else {
            outSig[ik] = lowSig[lk];
        }
        lk += lowStep;
        hk += highStep;
        ik += iStep;
        int i = 2;
        while (i < outLen - 1) {
            outSig[ik] = (lowSig[lk] / 0.8128931f) - ((0.44350687f * (highSig[hk - highStep] + highSig[hk])) / 1.2301741f);
            i += 2;
            ik += iStep;
            lk += lowStep;
            hk += highStep;
        }
        if (outLen % 2 == 1 && outLen > 2) {
            outSig[ik] = (lowSig[lk] / 0.8128931f) - ((0.88701373f * highSig[hk - highStep]) / 1.2301741f);
        }
        lk = lowOff;
        hk = highOff;
        ik = outOff + outStep;
        i = 1;
        while (i < outLen - 1) {
            outSig[ik] = (highSig[hk] / 1.2301741f) - (0.8829111f * (outSig[ik - outStep] + outSig[ik + outStep]));
            i += 2;
            ik += iStep;
            hk += highStep;
            lk += lowStep;
        }
        if (outLen % 2 == 0) {
            outSig[ik] = (highSig[hk] / 1.2301741f) - (1.7658222f * outSig[ik - outStep]);
        }
        ik = outOff;
        if (outLen > 1) {
            outSig[ik] = outSig[ik] - (-0.105960235f * outSig[ik + outStep]);
        }
        ik += iStep;
        i = 2;
        while (i < outLen - 1) {
            outSig[ik] = outSig[ik] - (-0.052980117f * (outSig[ik - outStep] + outSig[ik + outStep]));
            i += 2;
            ik += iStep;
        }
        if (outLen % 2 == 1 && outLen > 2) {
            outSig[ik] = outSig[ik] - (-0.105960235f * outSig[ik - outStep]);
        }
        ik = outOff + outStep;
        i = 1;
        while (i < outLen - 1) {
            outSig[ik] = outSig[ik] - (-1.5861343f * (outSig[ik - outStep] + outSig[ik + outStep]));
            i += 2;
            ik += iStep;
        }
        if (outLen % 2 == 0) {
            outSig[ik] = outSig[ik] - (-3.1722686f * outSig[ik - outStep]);
        }
    }

    public void synthetize_hpf(float[] lowSig, int lowOff, int lowLen, int lowStep, float[] highSig, int highOff, int highLen, int highStep, float[] outSig, int outOff, int outStep) {
        int i;
        int outLen = lowLen + highLen;
        int iStep = outStep * 2;
        int lk = lowOff;
        int hk = highOff;
        if (outLen != 1) {
            int outLen2 = outLen >> 1;
            for (i = 0; i < outLen2; i++) {
                lowSig[lk] = lowSig[lk] / 0.8128931f;
                highSig[hk] = highSig[hk] / 1.2301741f;
                lk += lowStep;
                hk += highStep;
            }
            if (outLen % 2 == 1) {
                highSig[hk] = highSig[hk] / 1.2301741f;
            }
        } else {
            highSig[highOff] = highSig[highOff] / 2.0f;
        }
        lk = lowOff;
        hk = highOff;
        int ik = outOff + outStep;
        for (i = 1; i < outLen - 1; i += 2) {
            outSig[ik] = lowSig[lk] - (0.44350687f * (highSig[hk] + highSig[hk + highStep]));
            ik += iStep;
            lk += lowStep;
            hk += highStep;
        }
        if (outLen % 2 == 0 && outLen > 1) {
            outSig[ik] = lowSig[lk] - (0.88701373f * highSig[hk]);
        }
        hk = highOff;
        ik = outOff;
        if (outLen > 1) {
            outSig[ik] = highSig[hk] - (1.7658222f * outSig[ik + outStep]);
        } else {
            outSig[ik] = highSig[hk];
        }
        ik += iStep;
        hk += highStep;
        for (i = 2; i < outLen - 1; i += 2) {
            outSig[ik] = highSig[hk] - (0.8829111f * (outSig[ik - outStep] + outSig[ik + outStep]));
            ik += iStep;
            hk += highStep;
        }
        if (outLen % 2 == 1 && outLen > 1) {
            outSig[ik] = highSig[hk] - (1.7658222f * outSig[ik - outStep]);
        }
        ik = outOff + outStep;
        for (i = 1; i < outLen - 1; i += 2) {
            outSig[ik] = outSig[ik] - (-0.052980117f * (outSig[ik - outStep] + outSig[ik + outStep]));
            ik += iStep;
        }
        if (outLen % 2 == 0 && outLen > 1) {
            outSig[ik] = outSig[ik] - (-0.105960235f * outSig[ik - outStep]);
        }
        ik = outOff;
        if (outLen > 1) {
            outSig[ik] = outSig[ik] - (-3.1722686f * outSig[ik + outStep]);
        }
        ik += iStep;
        for (i = 2; i < outLen - 1; i += 2) {
            outSig[ik] = outSig[ik] - (-1.5861343f * (outSig[ik - outStep] + outSig[ik + outStep]));
            ik += iStep;
        }
        if (outLen % 2 == 1 && outLen > 1) {
            outSig[ik] = outSig[ik] - (-3.1722686f * outSig[ik - outStep]);
        }
    }

    public int getAnLowNegSupport() {
        return 4;
    }

    public int getAnLowPosSupport() {
        return 4;
    }

    public int getAnHighNegSupport() {
        return 3;
    }

    public int getAnHighPosSupport() {
        return 3;
    }

    public int getSynLowNegSupport() {
        return 3;
    }

    public int getSynLowPosSupport() {
        return 3;
    }

    public int getSynHighNegSupport() {
        return 4;
    }

    public int getSynHighPosSupport() {
        return 4;
    }

    public int getImplType() {
        return 1;
    }

    public boolean isReversible() {
        return false;
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
        return "w9x7 (lifting)";
    }
}
