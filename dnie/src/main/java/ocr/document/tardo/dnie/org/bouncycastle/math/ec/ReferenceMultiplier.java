package org.bouncycastle.math.ec;

import java.math.BigInteger;

class ReferenceMultiplier implements ECMultiplier {
    ReferenceMultiplier() {
    }

    public ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger, PreCompInfo preCompInfo) {
        ECPoint infinity = eCPoint.getCurve().getInfinity();
        int bitLength = bigInteger.bitLength();
        ECPoint eCPoint2 = infinity;
        for (int i = 0; i < bitLength; i++) {
            if (bigInteger.testBit(i)) {
                eCPoint2 = eCPoint2.add(eCPoint);
            }
            eCPoint = eCPoint.twice();
        }
        return eCPoint2;
    }
}
