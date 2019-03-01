package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.spongycastle.math.ec.ECPoint.F2m;

class WTauNafMultiplier implements ECMultiplier {
    WTauNafMultiplier() {
    }

    public ECPoint multiply(ECPoint point, BigInteger k, PreCompInfo preCompInfo) {
        if (point instanceof F2m) {
            F2m p = (F2m) point;
            ECCurve.F2m curve = (ECCurve.F2m) p.getCurve();
            int m = curve.getM();
            byte a = curve.getA().toBigInteger().byteValue();
            byte mu = curve.getMu();
            return multiplyWTnaf(p, Tnaf.partModReduction(k, m, a, curve.getSi(), mu, (byte) 10), preCompInfo, a, mu);
        }
        throw new IllegalArgumentException("Only ECPoint.F2m can be used in WTauNafMultiplier");
    }

    private F2m multiplyWTnaf(F2m p, ZTauElement lambda, PreCompInfo preCompInfo, byte a, byte mu) {
        ZTauElement[] alpha;
        if (a == (byte) 0) {
            alpha = Tnaf.alpha0;
        } else {
            alpha = Tnaf.alpha1;
        }
        return multiplyFromWTnaf(p, Tnaf.tauAdicWNaf(mu, lambda, (byte) 4, BigInteger.valueOf(16), Tnaf.getTw(mu, 4), alpha), preCompInfo);
    }

    private static F2m multiplyFromWTnaf(F2m p, byte[] u, PreCompInfo preCompInfo) {
        F2m[] pu;
        byte a = ((ECCurve.F2m) p.getCurve()).getA().toBigInteger().byteValue();
        if (preCompInfo == null || !(preCompInfo instanceof WTauNafPreCompInfo)) {
            pu = Tnaf.getPreComp(p, a);
            p.setPreCompInfo(new WTauNafPreCompInfo(pu));
        } else {
            pu = ((WTauNafPreCompInfo) preCompInfo).getPreComp();
        }
        F2m q = (F2m) p.getCurve().getInfinity();
        for (int i = u.length - 1; i >= 0; i--) {
            q = Tnaf.tau(q);
            if (u[i] != (byte) 0) {
                if (u[i] > (byte) 0) {
                    q = q.addSimple(pu[u[i]]);
                } else {
                    q = q.subtractSimple(pu[-u[i]]);
                }
            }
        }
        return q;
    }
}
