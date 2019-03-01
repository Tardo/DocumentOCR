package org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.asn1.x9.X9IntegerConverter;

public abstract class ECPoint {
    private static X9IntegerConverter converter = new X9IntegerConverter();
    ECCurve curve;
    protected ECMultiplier multiplier = null;
    protected PreCompInfo preCompInfo = null;
    protected boolean withCompression;
    /* renamed from: x */
    ECFieldElement f114x;
    /* renamed from: y */
    ECFieldElement f115y;

    public static class F2m extends ECPoint {
        public F2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            this(eCCurve, eCFieldElement, eCFieldElement2, false);
        }

        public F2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, boolean z) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
            if ((eCFieldElement == null || eCFieldElement2 != null) && (eCFieldElement != null || eCFieldElement2 == null)) {
                if (eCFieldElement != null) {
                    org.bouncycastle.math.ec.ECFieldElement.F2m.checkFieldElements(this.x, this.y);
                    if (eCCurve != null) {
                        org.bouncycastle.math.ec.ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
                    }
                }
                this.withCompression = z;
                return;
            }
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        private static void checkPoints(ECPoint eCPoint, ECPoint eCPoint2) {
            if (!eCPoint.curve.equals(eCPoint2.curve)) {
                throw new IllegalArgumentException("Only points on the same curve can be added or subtracted");
            }
        }

        public ECPoint add(ECPoint eCPoint) {
            checkPoints(this, eCPoint);
            return addSimple((F2m) eCPoint);
        }

        public F2m addSimple(F2m f2m) {
            if (isInfinity()) {
                return f2m;
            }
            if (f2m.isInfinity()) {
                return this;
            }
            org.bouncycastle.math.ec.ECFieldElement.F2m f2m2 = (org.bouncycastle.math.ec.ECFieldElement.F2m) f2m.getX();
            org.bouncycastle.math.ec.ECFieldElement.F2m f2m3 = (org.bouncycastle.math.ec.ECFieldElement.F2m) f2m.getY();
            if (this.x.equals(f2m2)) {
                return this.y.equals(f2m3) ? (F2m) twice() : (F2m) this.curve.getInfinity();
            } else {
                f2m3 = (org.bouncycastle.math.ec.ECFieldElement.F2m) this.y.add(f2m3).divide(this.x.add(f2m2));
                f2m2 = (org.bouncycastle.math.ec.ECFieldElement.F2m) f2m3.square().add(f2m3).add(this.x).add(f2m2).add(this.curve.getA());
                return new F2m(this.curve, f2m2, (org.bouncycastle.math.ec.ECFieldElement.F2m) f2m3.multiply(this.x.add(f2m2)).add(f2m2).add(this.y), this.withCompression);
            }
        }

        synchronized void assertECMultiplier() {
            if (this.multiplier == null) {
                if (((org.bouncycastle.math.ec.ECCurve.F2m) this.curve).isKoblitz()) {
                    this.multiplier = new WTauNafMultiplier();
                } else {
                    this.multiplier = new WNafMultiplier();
                }
            }
        }

        public byte[] getEncoded(boolean z) {
            if (isInfinity()) {
                return new byte[1];
            }
            int byteLength = ECPoint.converter.getByteLength(this.x);
            Object integerToBytes = ECPoint.converter.integerToBytes(getX().toBigInteger(), byteLength);
            Object obj;
            if (z) {
                obj = new byte[(byteLength + 1)];
                obj[0] = (byte) 2;
                if (!getX().toBigInteger().equals(ECConstants.ZERO) && getY().multiply(getX().invert()).toBigInteger().testBit(0)) {
                    obj[0] = (byte) 3;
                }
                System.arraycopy(integerToBytes, 0, obj, 1, byteLength);
                return obj;
            }
            Object integerToBytes2 = ECPoint.converter.integerToBytes(getY().toBigInteger(), byteLength);
            obj = new byte[((byteLength + byteLength) + 1)];
            obj[0] = (byte) 4;
            System.arraycopy(integerToBytes, 0, obj, 1, byteLength);
            System.arraycopy(integerToBytes2, 0, obj, byteLength + 1, byteLength);
            return obj;
        }

        public ECPoint negate() {
            return new F2m(this.curve, getX(), getY().add(getX()), this.withCompression);
        }

        public ECPoint subtract(ECPoint eCPoint) {
            checkPoints(this, eCPoint);
            return subtractSimple((F2m) eCPoint);
        }

        public F2m subtractSimple(F2m f2m) {
            return f2m.isInfinity() ? this : addSimple((F2m) f2m.negate());
        }

        public ECPoint twice() {
            if (isInfinity()) {
                return this;
            }
            if (this.x.toBigInteger().signum() == 0) {
                return this.curve.getInfinity();
            }
            org.bouncycastle.math.ec.ECFieldElement.F2m f2m = (org.bouncycastle.math.ec.ECFieldElement.F2m) this.x.add(this.y.divide(this.x));
            org.bouncycastle.math.ec.ECFieldElement.F2m f2m2 = (org.bouncycastle.math.ec.ECFieldElement.F2m) f2m.square().add(f2m).add(this.curve.getA());
            return new F2m(this.curve, f2m2, (org.bouncycastle.math.ec.ECFieldElement.F2m) this.x.square().add(f2m2.multiply(f2m.add(this.curve.fromBigInteger(ECConstants.ONE)))), this.withCompression);
        }
    }

    public static class Fp extends ECPoint {
        public Fp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            this(eCCurve, eCFieldElement, eCFieldElement2, false);
        }

        public Fp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, boolean z) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
            if ((eCFieldElement == null || eCFieldElement2 != null) && (eCFieldElement != null || eCFieldElement2 == null)) {
                this.withCompression = z;
                return;
            }
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        public ECPoint add(ECPoint eCPoint) {
            if (isInfinity()) {
                return eCPoint;
            }
            if (eCPoint.isInfinity()) {
                return this;
            }
            if (this.x.equals(eCPoint.f114x)) {
                return this.y.equals(eCPoint.f115y) ? twice() : this.curve.getInfinity();
            } else {
                ECFieldElement divide = eCPoint.f115y.subtract(this.y).divide(eCPoint.f114x.subtract(this.x));
                ECFieldElement subtract = divide.square().subtract(this.x).subtract(eCPoint.f114x);
                return new Fp(this.curve, subtract, divide.multiply(this.x.subtract(subtract)).subtract(this.y), this.withCompression);
            }
        }

        synchronized void assertECMultiplier() {
            if (this.multiplier == null) {
                this.multiplier = new WNafMultiplier();
            }
        }

        public byte[] getEncoded(boolean z) {
            if (isInfinity()) {
                return new byte[1];
            }
            int byteLength = ECPoint.converter.getByteLength(this.x);
            if (z) {
                byte b = getY().toBigInteger().testBit(0) ? (byte) 3 : (byte) 2;
                Object integerToBytes = ECPoint.converter.integerToBytes(getX().toBigInteger(), byteLength);
                Object obj = new byte[(integerToBytes.length + 1)];
                obj[0] = b;
                System.arraycopy(integerToBytes, 0, obj, 1, integerToBytes.length);
                return obj;
            }
            integerToBytes = ECPoint.converter.integerToBytes(getX().toBigInteger(), byteLength);
            obj = ECPoint.converter.integerToBytes(getY().toBigInteger(), byteLength);
            Object obj2 = new byte[((integerToBytes.length + obj.length) + 1)];
            obj2[0] = (byte) 4;
            System.arraycopy(integerToBytes, 0, obj2, 1, integerToBytes.length);
            System.arraycopy(obj, 0, obj2, integerToBytes.length + 1, obj.length);
            return obj2;
        }

        public ECPoint negate() {
            return new Fp(this.curve, this.x, this.y.negate(), this.withCompression);
        }

        public ECPoint subtract(ECPoint eCPoint) {
            return eCPoint.isInfinity() ? this : add(eCPoint.negate());
        }

        public ECPoint twice() {
            if (isInfinity()) {
                return this;
            }
            if (this.y.toBigInteger().signum() == 0) {
                return this.curve.getInfinity();
            }
            ECFieldElement fromBigInteger = this.curve.fromBigInteger(BigInteger.valueOf(2));
            ECFieldElement divide = this.x.square().multiply(this.curve.fromBigInteger(BigInteger.valueOf(3))).add(this.curve.f112a).divide(this.y.multiply(fromBigInteger));
            ECFieldElement subtract = divide.square().subtract(this.x.multiply(fromBigInteger));
            return new Fp(this.curve, subtract, divide.multiply(this.x.subtract(subtract)).subtract(this.y), this.withCompression);
        }
    }

    protected ECPoint(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        this.curve = eCCurve;
        this.f114x = eCFieldElement;
        this.f115y = eCFieldElement2;
    }

    public abstract ECPoint add(ECPoint eCPoint);

    synchronized void assertECMultiplier() {
        if (this.multiplier == null) {
            this.multiplier = new FpNafMultiplier();
        }
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ECPoint)) {
            return false;
        }
        ECPoint eCPoint = (ECPoint) obj;
        return isInfinity() ? eCPoint.isInfinity() : this.f114x.equals(eCPoint.f114x) && this.f115y.equals(eCPoint.f115y);
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public byte[] getEncoded() {
        return getEncoded(this.withCompression);
    }

    public abstract byte[] getEncoded(boolean z);

    public ECFieldElement getX() {
        return this.f114x;
    }

    public ECFieldElement getY() {
        return this.f115y;
    }

    public int hashCode() {
        return isInfinity() ? 0 : this.f114x.hashCode() ^ this.f115y.hashCode();
    }

    public boolean isCompressed() {
        return this.withCompression;
    }

    public boolean isInfinity() {
        return this.f114x == null && this.f115y == null;
    }

    public ECPoint multiply(BigInteger bigInteger) {
        if (bigInteger.signum() < 0) {
            throw new IllegalArgumentException("The multiplicator cannot be negative");
        } else if (isInfinity()) {
            return this;
        } else {
            if (bigInteger.signum() == 0) {
                return this.curve.getInfinity();
            }
            assertECMultiplier();
            return this.multiplier.multiply(this, bigInteger, this.preCompInfo);
        }
    }

    public abstract ECPoint negate();

    void setPreCompInfo(PreCompInfo preCompInfo) {
        this.preCompInfo = preCompInfo;
    }

    public abstract ECPoint subtract(ECPoint eCPoint);

    public abstract ECPoint twice();
}
