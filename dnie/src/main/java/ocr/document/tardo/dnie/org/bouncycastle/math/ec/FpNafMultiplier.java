package org.bouncycastle.math.ec;

import java.math.BigInteger;

class FpNafMultiplier implements ECMultiplier {
    FpNafMultiplier() {
    }

    public ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger, PreCompInfo preCompInfo) {
        BigInteger multiply = bigInteger.multiply(BigInteger.valueOf(3));
        ECPoint negate = eCPoint.negate();
        ECPoint eCPoint2 = eCPoint;
        for (int bitLength = multiply.bitLength() - 2; bitLength > 0; bitLength--) {
            ECPoint twice = eCPoint2.twice();
            boolean testBit = multiply.testBit(bitLength);
            if (testBit != bigInteger.testBit(bitLength)) {
                eCPoint2 = twice.add(testBit ? eCPoint : negate);
            } else {
                eCPoint2 = twice;
            }
        }
        return eCPoint2;
    }
}
