package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.spongycastle.math.ec.ECCurve.F2m;

public class ECAlgorithms {
    public static ECPoint sumOfTwoMultiplies(ECPoint P, BigInteger a, ECPoint Q, BigInteger b) {
        ECCurve c = P.getCurve();
        if (!c.equals(Q.getCurve())) {
            throw new IllegalArgumentException("P and Q must be on same curve");
        } else if ((c instanceof F2m) && ((F2m) c).isKoblitz()) {
            return P.multiply(a).add(Q.multiply(b));
        } else {
            return implShamirsTrick(P, a, Q, b);
        }
    }

    public static ECPoint shamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
        if (P.getCurve().equals(Q.getCurve())) {
            return implShamirsTrick(P, k, Q, l);
        }
        throw new IllegalArgumentException("P and Q must be on same curve");
    }

    private static ECPoint implShamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
        int m = Math.max(k.bitLength(), l.bitLength());
        ECPoint Z = P.add(Q);
        ECPoint R = P.getCurve().getInfinity();
        for (int i = m - 1; i >= 0; i--) {
            R = R.twice();
            if (k.testBit(i)) {
                if (l.testBit(i)) {
                    R = R.add(Z);
                } else {
                    R = R.add(P);
                }
            } else if (l.testBit(i)) {
                R = R.add(Q);
            }
        }
        return R;
    }
}
