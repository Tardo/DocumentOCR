package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.spongycastle.asn1.x9.X9IntegerConverter;

public abstract class ECPoint {
    private static X9IntegerConverter converter = new X9IntegerConverter();
    ECCurve curve;
    protected ECMultiplier multiplier = null;
    protected PreCompInfo preCompInfo = null;
    protected boolean withCompression;
    /* renamed from: x */
    ECFieldElement f199x;
    /* renamed from: y */
    ECFieldElement f200y;

    public static class F2m extends ECPoint {
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y) {
            this(curve, x, y, false);
        }

        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression) {
            super(curve, x, y);
            if ((x == null || y != null) && (x != null || y == null)) {
                if (x != null) {
                    org.spongycastle.math.ec.ECFieldElement.F2m.checkFieldElements(this.x, this.y);
                    if (curve != null) {
                        org.spongycastle.math.ec.ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
                    }
                }
                this.withCompression = withCompression;
                return;
            }
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        public byte[] getEncoded() {
            if (isInfinity()) {
                return new byte[1];
            }
            int byteCount = ECPoint.converter.getByteLength(this.x);
            byte[] X = ECPoint.converter.integerToBytes(getX().toBigInteger(), byteCount);
            byte[] PO;
            if (this.withCompression) {
                PO = new byte[(byteCount + 1)];
                PO[0] = (byte) 2;
                if (!getX().toBigInteger().equals(ECConstants.ZERO) && getY().multiply(getX().invert()).toBigInteger().testBit(0)) {
                    PO[0] = (byte) 3;
                }
                System.arraycopy(X, 0, PO, 1, byteCount);
                return PO;
            }
            byte[] Y = ECPoint.converter.integerToBytes(getY().toBigInteger(), byteCount);
            PO = new byte[((byteCount + byteCount) + 1)];
            PO[0] = (byte) 4;
            System.arraycopy(X, 0, PO, 1, byteCount);
            System.arraycopy(Y, 0, PO, byteCount + 1, byteCount);
            return PO;
        }

        private static void checkPoints(ECPoint a, ECPoint b) {
            if (!a.curve.equals(b.curve)) {
                throw new IllegalArgumentException("Only points on the same curve can be added or subtracted");
            }
        }

        public ECPoint add(ECPoint b) {
            checkPoints(this, b);
            return addSimple((F2m) b);
        }

        public F2m addSimple(F2m b) {
            F2m other = b;
            if (isInfinity()) {
                return other;
            }
            if (other.isInfinity()) {
                return this;
            }
            org.spongycastle.math.ec.ECFieldElement.F2m x2 = (org.spongycastle.math.ec.ECFieldElement.F2m) other.getX();
            org.spongycastle.math.ec.ECFieldElement.F2m y2 = (org.spongycastle.math.ec.ECFieldElement.F2m) other.getY();
            if (!this.x.equals(x2)) {
                org.spongycastle.math.ec.ECFieldElement.F2m lambda = (org.spongycastle.math.ec.ECFieldElement.F2m) this.y.add(y2).divide(this.x.add(x2));
                org.spongycastle.math.ec.ECFieldElement.F2m x3 = (org.spongycastle.math.ec.ECFieldElement.F2m) lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.getA());
                return new F2m(this.curve, x3, (org.spongycastle.math.ec.ECFieldElement.F2m) lambda.multiply(this.x.add(x3)).add(x3).add(this.y), this.withCompression);
            } else if (this.y.equals(y2)) {
                return (F2m) twice();
            } else {
                return (F2m) this.curve.getInfinity();
            }
        }

        public ECPoint subtract(ECPoint b) {
            checkPoints(this, b);
            return subtractSimple((F2m) b);
        }

        public F2m subtractSimple(F2m b) {
            return b.isInfinity() ? this : addSimple((F2m) b.negate());
        }

        public ECPoint twice() {
            if (isInfinity()) {
                return this;
            }
            if (this.x.toBigInteger().signum() == 0) {
                return this.curve.getInfinity();
            }
            org.spongycastle.math.ec.ECFieldElement.F2m lambda = (org.spongycastle.math.ec.ECFieldElement.F2m) this.x.add(this.y.divide(this.x));
            org.spongycastle.math.ec.ECFieldElement.F2m x3 = (org.spongycastle.math.ec.ECFieldElement.F2m) lambda.square().add(lambda).add(this.curve.getA());
            return new F2m(this.curve, x3, (org.spongycastle.math.ec.ECFieldElement.F2m) this.x.square().add(x3.multiply(lambda.add(this.curve.fromBigInteger(ECConstants.ONE)))), this.withCompression);
        }

        public ECPoint negate() {
            return new F2m(this.curve, getX(), getY().add(getX()), this.withCompression);
        }

        synchronized void assertECMultiplier() {
            if (this.multiplier == null) {
                if (((org.spongycastle.math.ec.ECCurve.F2m) this.curve).isKoblitz()) {
                    this.multiplier = new WTauNafMultiplier();
                } else {
                    this.multiplier = new WNafMultiplier();
                }
            }
        }
    }

    public static class Fp extends ECPoint {
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y) {
            this(curve, x, y, false);
        }

        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression) {
            super(curve, x, y);
            if ((x == null || y != null) && (x != null || y == null)) {
                this.withCompression = withCompression;
                return;
            }
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        public byte[] getEncoded() {
            if (isInfinity()) {
                return new byte[1];
            }
            int qLength = ECPoint.converter.getByteLength(this.x);
            if (this.withCompression) {
                byte PC;
                if (getY().toBigInteger().testBit(0)) {
                    PC = (byte) 3;
                } else {
                    PC = (byte) 2;
                }
                byte[] X = ECPoint.converter.integerToBytes(getX().toBigInteger(), qLength);
                byte[] PO = new byte[(X.length + 1)];
                PO[0] = PC;
                System.arraycopy(X, 0, PO, 1, X.length);
                return PO;
            }
            X = ECPoint.converter.integerToBytes(getX().toBigInteger(), qLength);
            byte[] Y = ECPoint.converter.integerToBytes(getY().toBigInteger(), qLength);
            PO = new byte[((X.length + Y.length) + 1)];
            PO[0] = (byte) 4;
            System.arraycopy(X, 0, PO, 1, X.length);
            System.arraycopy(Y, 0, PO, X.length + 1, Y.length);
            return PO;
        }

        public ECPoint add(ECPoint b) {
            if (isInfinity()) {
                return b;
            }
            if (b.isInfinity()) {
                return this;
            }
            if (!this.x.equals(b.f199x)) {
                ECFieldElement gamma = b.f200y.subtract(this.y).divide(b.f199x.subtract(this.x));
                ECFieldElement x3 = gamma.square().subtract(this.x).subtract(b.f199x);
                return new Fp(this.curve, x3, gamma.multiply(this.x.subtract(x3)).subtract(this.y));
            } else if (this.y.equals(b.f200y)) {
                return twice();
            } else {
                return this.curve.getInfinity();
            }
        }

        public ECPoint twice() {
            if (isInfinity()) {
                return this;
            }
            if (this.y.toBigInteger().signum() == 0) {
                return this.curve.getInfinity();
            }
            ECFieldElement TWO = this.curve.fromBigInteger(BigInteger.valueOf(2));
            ECFieldElement gamma = this.x.square().multiply(this.curve.fromBigInteger(BigInteger.valueOf(3))).add(this.curve.f197a).divide(this.y.multiply(TWO));
            ECFieldElement x3 = gamma.square().subtract(this.x.multiply(TWO));
            return new Fp(this.curve, x3, gamma.multiply(this.x.subtract(x3)).subtract(this.y), this.withCompression);
        }

        public ECPoint subtract(ECPoint b) {
            return b.isInfinity() ? this : add(b.negate());
        }

        public ECPoint negate() {
            return new Fp(this.curve, this.x, this.y.negate(), this.withCompression);
        }

        synchronized void assertECMultiplier() {
            if (this.multiplier == null) {
                this.multiplier = new WNafMultiplier();
            }
        }
    }

    public abstract ECPoint add(ECPoint eCPoint);

    public abstract byte[] getEncoded();

    public abstract ECPoint negate();

    public abstract ECPoint subtract(ECPoint eCPoint);

    public abstract ECPoint twice();

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        this.curve = curve;
        this.f199x = x;
        this.f200y = y;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECFieldElement getX() {
        return this.f199x;
    }

    public ECFieldElement getY() {
        return this.f200y;
    }

    public boolean isInfinity() {
        return this.f199x == null && this.f200y == null;
    }

    public boolean isCompressed() {
        return this.withCompression;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof ECPoint)) {
            return false;
        }
        ECPoint o = (ECPoint) other;
        if (isInfinity()) {
            return o.isInfinity();
        }
        if (this.f199x.equals(o.f199x) && this.f200y.equals(o.f200y)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        if (isInfinity()) {
            return 0;
        }
        return this.f199x.hashCode() ^ this.f200y.hashCode();
    }

    void setPreCompInfo(PreCompInfo preCompInfo) {
        this.preCompInfo = preCompInfo;
    }

    synchronized void assertECMultiplier() {
        if (this.multiplier == null) {
            this.multiplier = new FpNafMultiplier();
        }
    }

    public ECPoint multiply(BigInteger k) {
        if (k.signum() < 0) {
            throw new IllegalArgumentException("The multiplicator cannot be negative");
        } else if (isInfinity()) {
            return this;
        } else {
            if (k.signum() == 0) {
                return this.curve.getInfinity();
            }
            assertECMultiplier();
            return this.multiplier.multiply(this, k, this.preCompInfo);
        }
    }
}
