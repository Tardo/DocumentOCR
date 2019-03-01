package org.bouncycastle.math.ec;

class WNafPreCompInfo implements PreCompInfo {
    private ECPoint[] preComp = null;
    private ECPoint twiceP = null;

    WNafPreCompInfo() {
    }

    protected ECPoint[] getPreComp() {
        return this.preComp;
    }

    protected ECPoint getTwiceP() {
        return this.twiceP;
    }

    protected void setPreComp(ECPoint[] eCPointArr) {
        this.preComp = eCPointArr;
    }

    protected void setTwiceP(ECPoint eCPoint) {
        this.twiceP = eCPoint;
    }
}
