package org.spongycastle.jce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.math.ec.ECCurve.Fp;

public class EC5Util {
    public static EllipticCurve convertCurve(ECCurve curve, byte[] seed) {
        if (curve instanceof Fp) {
            return new EllipticCurve(new ECFieldFp(((Fp) curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), null);
        }
        F2m curveF2m = (F2m) curve;
        if (curveF2m.isTrinomial()) {
            return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), new int[]{curveF2m.getK1()}), curve.getA().toBigInteger(), curve.getB().toBigInteger(), null);
        }
        return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), new int[]{curveF2m.getK3(), curveF2m.getK2(), curveF2m.getK1()}), curve.getA().toBigInteger(), curve.getB().toBigInteger(), null);
    }

    public static ECCurve convertCurve(EllipticCurve ec) {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();
        if (field instanceof ECFieldFp) {
            return new Fp(((ECFieldFp) field).getP(), a, b);
        }
        ECFieldF2m fieldF2m = (ECFieldF2m) field;
        int m = fieldF2m.getM();
        int[] ks = ECUtil.convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
        return new F2m(m, ks[0], ks[1], ks[2], a, b);
    }

    public static ECParameterSpec convertSpec(EllipticCurve ellipticCurve, org.spongycastle.jce.spec.ECParameterSpec spec) {
        if (!(spec instanceof ECNamedCurveParameterSpec)) {
            return new ECParameterSpec(ellipticCurve, new ECPoint(spec.getG().getX().toBigInteger(), spec.getG().getY().toBigInteger()), spec.getN(), spec.getH().intValue());
        }
        return new ECNamedCurveSpec(((ECNamedCurveParameterSpec) spec).getName(), ellipticCurve, new ECPoint(spec.getG().getX().toBigInteger(), spec.getG().getY().toBigInteger()), spec.getN(), spec.getH());
    }

    public static org.spongycastle.jce.spec.ECParameterSpec convertSpec(ECParameterSpec ecSpec, boolean withCompression) {
        ECCurve curve = convertCurve(ecSpec.getCurve());
        return new org.spongycastle.jce.spec.ECParameterSpec(curve, convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf((long) ecSpec.getCofactor()), ecSpec.getCurve().getSeed());
    }

    public static org.spongycastle.math.ec.ECPoint convertPoint(ECParameterSpec ecSpec, ECPoint point, boolean withCompression) {
        return convertPoint(convertCurve(ecSpec.getCurve()), point, withCompression);
    }

    public static org.spongycastle.math.ec.ECPoint convertPoint(ECCurve curve, ECPoint point, boolean withCompression) {
        return curve.createPoint(point.getAffineX(), point.getAffineY(), withCompression);
    }
}
