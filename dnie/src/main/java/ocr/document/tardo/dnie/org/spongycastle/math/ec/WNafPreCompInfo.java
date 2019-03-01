package org.spongycastle.math.ec;

class WNafPreCompInfo implements PreCompInfo {
    private ECPoint[] preComp = null;
    private ECPoint twiceP = null;

    WNafPreCompInfo() {
    }

    protected ECPoint[] getPreComp() {
        return this.preComp;
    }

    protected void setPreComp(ECPoint[] preComp) {
        this.preComp = preComp;
    }

    protected ECPoint getTwiceP() {
        return this.twiceP;
    }

    protected void setTwiceP(ECPoint twiceThis) {
        this.twiceP = twiceThis;
    }
}
