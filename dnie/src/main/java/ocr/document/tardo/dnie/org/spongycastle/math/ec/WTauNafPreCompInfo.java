package org.spongycastle.math.ec;

import org.spongycastle.math.ec.ECPoint.F2m;

class WTauNafPreCompInfo implements PreCompInfo {
    private F2m[] preComp = null;

    WTauNafPreCompInfo(F2m[] preComp) {
        this.preComp = preComp;
    }

    protected F2m[] getPreComp() {
        return this.preComp;
    }
}
