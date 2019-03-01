package org.bouncycastle.math.ec;

import org.bouncycastle.math.ec.ECPoint.F2m;

class WTauNafPreCompInfo implements PreCompInfo {
    private F2m[] preComp = null;

    WTauNafPreCompInfo(F2m[] f2mArr) {
        this.preComp = f2mArr;
    }

    protected F2m[] getPreComp() {
        return this.preComp;
    }
}
