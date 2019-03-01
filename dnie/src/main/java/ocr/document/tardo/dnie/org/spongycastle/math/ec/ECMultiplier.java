package org.spongycastle.math.ec;

import java.math.BigInteger;

interface ECMultiplier {
    ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger, PreCompInfo preCompInfo);
}
