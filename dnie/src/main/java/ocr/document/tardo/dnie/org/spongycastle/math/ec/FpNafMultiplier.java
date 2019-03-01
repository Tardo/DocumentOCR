package org.spongycastle.math.ec;

import java.math.BigInteger;

class FpNafMultiplier implements ECMultiplier {
    FpNafMultiplier() {
    }

    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo) {
        BigInteger e = k;
        BigInteger h = e.multiply(BigInteger.valueOf(3));
        ECPoint neg = p.negate();
        ECPoint R = p;
        for (int i = h.bitLength() - 2; i > 0; i--) {
            R = R.twice();
            boolean hBit = h.testBit(i);
            if (hBit != e.testBit(i)) {
                R = R.add(hBit ? p : neg);
            }
        }
        return R;
    }
}
