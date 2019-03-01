package org.spongycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.math.ec.ECCurve.Fp;

public class ECNamedCurveSpec extends ECParameterSpec {
    private String name;

    private static EllipticCurve convertCurve(ECCurve curve, byte[] seed) {
        if (curve instanceof Fp) {
            return new EllipticCurve(new ECFieldFp(((Fp) curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
        }
        F2m curveF2m = (F2m) curve;
        if (curveF2m.isTrinomial()) {
            return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), new int[]{curveF2m.getK1()}), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
        }
        return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), new int[]{curveF2m.getK3(), curveF2m.getK2(), curveF2m.getK1()}), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
    }

    private static ECPoint convertPoint(org.spongycastle.math.ec.ECPoint g) {
        return new ECPoint(g.getX().toBigInteger(), g.getY().toBigInteger());
    }

    public ECNamedCurveSpec(String name, ECCurve curve, org.spongycastle.math.ec.ECPoint g, BigInteger n) {
        super(convertCurve(curve, null), convertPoint(g), n, 1);
        this.name = name;
    }

    public ECNamedCurveSpec(String name, EllipticCurve curve, ECPoint g, BigInteger n) {
        super(curve, g, n, 1);
        this.name = name;
    }

    public ECNamedCurveSpec(String name, ECCurve curve, org.spongycastle.math.ec.ECPoint g, BigInteger n, BigInteger h) {
        super(convertCurve(curve, null), convertPoint(g), n, h.intValue());
        this.name = name;
    }

    public ECNamedCurveSpec(String name, EllipticCurve curve, ECPoint g, BigInteger n, BigInteger h) {
        super(curve, g, n, h.intValue());
        this.name = name;
    }

    public ECNamedCurveSpec(String name, ECCurve curve, org.spongycastle.math.ec.ECPoint g, BigInteger n, BigInteger h, byte[] seed) {
        super(convertCurve(curve, seed), convertPoint(g), n, h.intValue());
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
}
