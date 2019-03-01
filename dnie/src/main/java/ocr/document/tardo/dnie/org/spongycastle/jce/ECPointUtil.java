package org.spongycastle.jce;

import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.math.ec.ECCurve.Fp;

public class ECPointUtil {
    public static ECPoint decodePoint(EllipticCurve curve, byte[] encoded) {
        ECCurve c;
        if (curve.getField() instanceof ECFieldFp) {
            c = new Fp(((ECFieldFp) curve.getField()).getP(), curve.getA(), curve.getB());
        } else {
            int[] k = ((ECFieldF2m) curve.getField()).getMidTermsOfReductionPolynomial();
            if (k.length == 3) {
                c = new F2m(((ECFieldF2m) curve.getField()).getM(), k[2], k[1], k[0], curve.getA(), curve.getB());
            } else {
                c = new F2m(((ECFieldF2m) curve.getField()).getM(), k[0], curve.getA(), curve.getB());
            }
        }
        org.spongycastle.math.ec.ECPoint p = c.decodePoint(encoded);
        return new ECPoint(p.getX().toBigInteger(), p.getY().toBigInteger());
    }
}
