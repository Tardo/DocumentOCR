package org.bouncycastle.asn1.ua;

import java.math.BigInteger;
import java.util.Random;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public abstract class DSTU4145PointEncoder {
    private static X9IntegerConverter converter = new X9IntegerConverter();

    public static ECPoint decodePoint(ECCurve eCCurve, byte[] bArr) {
        ECFieldElement eCFieldElement;
        BigInteger valueOf = BigInteger.valueOf((long) (bArr[bArr.length - 1] & 1));
        if (!trace(eCCurve.fromBigInteger(new BigInteger(1, bArr))).equals(eCCurve.getA().toBigInteger())) {
            bArr = Arrays.clone(bArr);
            int length = bArr.length - 1;
            bArr[length] = (byte) (bArr[length] ^ 1);
        }
        F2m f2m = (F2m) eCCurve;
        ECFieldElement fromBigInteger = eCCurve.fromBigInteger(new BigInteger(1, bArr));
        if (fromBigInteger.toBigInteger().equals(ECConstants.ZERO)) {
            eCFieldElement = (ECFieldElement.F2m) eCCurve.getB();
            for (int i = 0; i < f2m.getM() - 1; i++) {
                eCFieldElement = eCFieldElement.square();
            }
        } else {
            ECFieldElement solveQuadradicEquation = solveQuadradicEquation(fromBigInteger.add(eCCurve.getA()).add(eCCurve.getB().multiply(fromBigInteger.square().invert())));
            if (solveQuadradicEquation == null) {
                throw new RuntimeException("Invalid point compression");
            }
            if (!trace(solveQuadradicEquation).equals(valueOf)) {
                solveQuadradicEquation = solveQuadradicEquation.add(eCCurve.fromBigInteger(ECConstants.ONE));
            }
            eCFieldElement = fromBigInteger.multiply(solveQuadradicEquation);
        }
        return new ECPoint.F2m(eCCurve, fromBigInteger, eCFieldElement);
    }

    public static byte[] encodePoint(ECPoint eCPoint) {
        byte[] integerToBytes = converter.integerToBytes(eCPoint.getX().toBigInteger(), converter.getByteLength(eCPoint.getX()));
        if (!eCPoint.getX().toBigInteger().equals(ECConstants.ZERO)) {
            int length;
            if (trace(eCPoint.getY().multiply(eCPoint.getX().invert())).equals(ECConstants.ONE)) {
                length = integerToBytes.length - 1;
                integerToBytes[length] = (byte) (integerToBytes[length] | 1);
            } else {
                length = integerToBytes.length - 1;
                integerToBytes[length] = (byte) (integerToBytes[length] & 254);
            }
        }
        return integerToBytes;
    }

    private static ECFieldElement solveQuadradicEquation(ECFieldElement eCFieldElement) {
        ECFieldElement.F2m f2m = (ECFieldElement.F2m) eCFieldElement;
        ECFieldElement f2m2 = new ECFieldElement.F2m(f2m.getM(), f2m.getK1(), f2m.getK2(), f2m.getK3(), ECConstants.ZERO);
        if (eCFieldElement.toBigInteger().equals(ECConstants.ZERO)) {
            return f2m2;
        }
        ECFieldElement eCFieldElement2;
        Random random = new Random();
        int m = f2m.getM();
        do {
            ECFieldElement f2m3 = new ECFieldElement.F2m(f2m.getM(), f2m.getK1(), f2m.getK2(), f2m.getK3(), new BigInteger(m, random));
            int i = 1;
            ECFieldElement eCFieldElement3 = eCFieldElement;
            eCFieldElement2 = f2m2;
            while (i <= m - 1) {
                eCFieldElement3 = eCFieldElement3.square();
                ECFieldElement add = eCFieldElement2.square().add(eCFieldElement3.multiply(f2m3));
                eCFieldElement3 = eCFieldElement3.add(eCFieldElement);
                i++;
                eCFieldElement2 = add;
            }
            if (!eCFieldElement3.toBigInteger().equals(ECConstants.ZERO)) {
                return null;
            }
        } while (eCFieldElement2.square().add(eCFieldElement2).toBigInteger().equals(ECConstants.ZERO));
        return eCFieldElement2;
    }

    private static BigInteger trace(ECFieldElement eCFieldElement) {
        ECFieldElement eCFieldElement2 = eCFieldElement;
        for (int i = 0; i < eCFieldElement.getFieldSize() - 1; i++) {
            eCFieldElement2 = eCFieldElement2.square().add(eCFieldElement);
        }
        return eCFieldElement2.toBigInteger();
    }
}
