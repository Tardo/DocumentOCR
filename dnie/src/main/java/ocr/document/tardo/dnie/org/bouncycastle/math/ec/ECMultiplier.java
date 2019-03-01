package org.bouncycastle.math.ec;

import java.math.BigInteger;

interface ECMultiplier {
    ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger, PreCompInfo preCompInfo);
}
