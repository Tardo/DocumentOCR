package org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.util.Random;

public abstract class ECCurve {
    /* renamed from: a */
    ECFieldElement f112a;
    /* renamed from: b */
    ECFieldElement f113b;

    public static class F2m extends ECCurve {
        /* renamed from: h */
        private BigInteger f305h;
        private org.bouncycastle.math.ec.ECPoint.F2m infinity;
        private int k1;
        private int k2;
        private int k3;
        /* renamed from: m */
        private int f306m;
        private byte mu;
        /* renamed from: n */
        private BigInteger f307n;
        private BigInteger[] si;

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, i3, i4, bigInteger, bigInteger2, null, null);
        }

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            this.mu = (byte) 0;
            this.si = null;
            this.f306m = i;
            this.k1 = i2;
            this.k2 = i3;
            this.k3 = i4;
            this.f307n = bigInteger3;
            this.f305h = bigInteger4;
            if (i2 == 0) {
                throw new IllegalArgumentException("k1 must be > 0");
            }
            if (i3 == 0) {
                if (i4 != 0) {
                    throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
                }
            } else if (i3 <= i2) {
                throw new IllegalArgumentException("k2 must be > k1");
            } else if (i4 <= i3) {
                throw new IllegalArgumentException("k3 must be > k2");
            }
            this.a = fromBigInteger(bigInteger);
            this.b = fromBigInteger(bigInteger2);
            this.infinity = new org.bouncycastle.math.ec.ECPoint.F2m(this, null, null);
        }

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, null, null);
        }

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, bigInteger3, bigInteger4);
        }

        private ECFieldElement solveQuadradicEquation(ECFieldElement eCFieldElement) {
            ECFieldElement f2m = new org.bouncycastle.math.ec.ECFieldElement.F2m(this.f306m, this.k1, this.k2, this.k3, ECConstants.ZERO);
            if (eCFieldElement.toBigInteger().equals(ECConstants.ZERO)) {
                return f2m;
            }
            ECFieldElement eCFieldElement2;
            Random random = new Random();
            do {
                ECFieldElement f2m2 = new org.bouncycastle.math.ec.ECFieldElement.F2m(this.f306m, this.k1, this.k2, this.k3, new BigInteger(this.f306m, random));
                ECFieldElement eCFieldElement3 = eCFieldElement;
                eCFieldElement2 = f2m;
                for (int i = 1; i <= this.f306m - 1; i++) {
                    eCFieldElement3 = eCFieldElement3.square();
                    eCFieldElement2 = eCFieldElement2.square().add(eCFieldElement3.multiply(f2m2));
                    eCFieldElement3 = eCFieldElement3.add(eCFieldElement);
                }
                if (!eCFieldElement3.toBigInteger().equals(ECConstants.ZERO)) {
                    return null;
                }
            } while (eCFieldElement2.square().add(eCFieldElement2).toBigInteger().equals(ECConstants.ZERO));
            return eCFieldElement2;
        }

        public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2, boolean z) {
            return new org.bouncycastle.math.ec.ECPoint.F2m(this, fromBigInteger(bigInteger), fromBigInteger(bigInteger2), z);
        }

        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            ECFieldElement eCFieldElement;
            int i2 = 0;
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            if (fromBigInteger.toBigInteger().equals(ECConstants.ZERO)) {
                eCFieldElement = (org.bouncycastle.math.ec.ECFieldElement.F2m) this.b;
                for (int i3 = 0; i3 < this.f306m - 1; i3++) {
                    eCFieldElement = eCFieldElement.square();
                }
            } else {
                ECFieldElement solveQuadradicEquation = solveQuadradicEquation(fromBigInteger.add(this.a).add(this.b.multiply(fromBigInteger.square().invert())));
                if (solveQuadradicEquation == null) {
                    throw new IllegalArgumentException("Invalid point compression");
                }
                if (solveQuadradicEquation.toBigInteger().testBit(0)) {
                    i2 = 1;
                }
                if (i2 != i) {
                    solveQuadradicEquation = solveQuadradicEquation.add(fromBigInteger(ECConstants.ONE));
                }
                eCFieldElement = fromBigInteger.multiply(solveQuadradicEquation);
            }
            return new org.bouncycastle.math.ec.ECPoint.F2m(this, fromBigInteger, eCFieldElement, true);
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof F2m)) {
                return false;
            }
            F2m f2m = (F2m) obj;
            return this.f306m == f2m.f306m && this.k1 == f2m.k1 && this.k2 == f2m.k2 && this.k3 == f2m.k3 && this.a.equals(f2m.a) && this.b.equals(f2m.b);
        }

        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            return new org.bouncycastle.math.ec.ECFieldElement.F2m(this.f306m, this.k1, this.k2, this.k3, bigInteger);
        }

        public int getFieldSize() {
            return this.f306m;
        }

        public BigInteger getH() {
            return this.f305h;
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }

        public int getK1() {
            return this.k1;
        }

        public int getK2() {
            return this.k2;
        }

        public int getK3() {
            return this.k3;
        }

        public int getM() {
            return this.f306m;
        }

        synchronized byte getMu() {
            if (this.mu == (byte) 0) {
                this.mu = Tnaf.getMu(this);
            }
            return this.mu;
        }

        public BigInteger getN() {
            return this.f307n;
        }

        synchronized BigInteger[] getSi() {
            if (this.si == null) {
                this.si = Tnaf.getSi(this);
            }
            return this.si;
        }

        public int hashCode() {
            return ((((this.a.hashCode() ^ this.b.hashCode()) ^ this.f306m) ^ this.k1) ^ this.k2) ^ this.k3;
        }

        public boolean isKoblitz() {
            return (this.f307n == null || this.f305h == null || ((!this.a.toBigInteger().equals(ECConstants.ZERO) && !this.a.toBigInteger().equals(ECConstants.ONE)) || !this.b.toBigInteger().equals(ECConstants.ONE))) ? false : true;
        }

        public boolean isTrinomial() {
            return this.k2 == 0 && this.k3 == 0;
        }
    }

    public static class Fp extends ECCurve {
        org.bouncycastle.math.ec.ECPoint.Fp infinity = new org.bouncycastle.math.ec.ECPoint.Fp(this, null, null);
        /* renamed from: q */
        BigInteger f308q;

        public Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            this.f308q = bigInteger;
            this.a = fromBigInteger(bigInteger2);
            this.b = fromBigInteger(bigInteger3);
        }

        public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2, boolean z) {
            return new org.bouncycastle.math.ec.ECPoint.Fp(this, fromBigInteger(bigInteger), fromBigInteger(bigInteger2), z);
        }

        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            int i2 = 0;
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement sqrt = fromBigInteger.multiply(fromBigInteger.square().add(this.a)).add(this.b).sqrt();
            if (sqrt == null) {
                throw new RuntimeException("Invalid point compression");
            }
            BigInteger toBigInteger = sqrt.toBigInteger();
            if (toBigInteger.testBit(0)) {
                i2 = 1;
            }
            if (i2 != i) {
                sqrt = fromBigInteger(this.f308q.subtract(toBigInteger));
            }
            return new org.bouncycastle.math.ec.ECPoint.Fp(this, fromBigInteger, sqrt, true);
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof Fp)) {
                return false;
            }
            Fp fp = (Fp) obj;
            return this.f308q.equals(fp.f308q) && this.a.equals(fp.a) && this.b.equals(fp.b);
        }

        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            return new org.bouncycastle.math.ec.ECFieldElement.Fp(this.f308q, bigInteger);
        }

        public int getFieldSize() {
            return this.f308q.bitLength();
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }

        public BigInteger getQ() {
            return this.f308q;
        }

        public int hashCode() {
            return (this.a.hashCode() ^ this.b.hashCode()) ^ this.f308q.hashCode();
        }
    }

    private static BigInteger fromArray(byte[] bArr, int i, int i2) {
        Object obj = new byte[i2];
        System.arraycopy(bArr, i, obj, 0, i2);
        return new BigInteger(1, obj);
    }

    public abstract ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2, boolean z);

    public ECPoint decodePoint(byte[] bArr) {
        int fieldSize = (getFieldSize() + 7) / 8;
        switch (bArr[0]) {
            case (byte) 0:
                if (bArr.length == 1) {
                    return getInfinity();
                }
                throw new IllegalArgumentException("Incorrect length for infinity encoding");
            case (byte) 2:
            case (byte) 3:
                if (bArr.length == fieldSize + 1) {
                    return decompressPoint(bArr[0] & 1, fromArray(bArr, 1, fieldSize));
                }
                throw new IllegalArgumentException("Incorrect length for compressed encoding");
            case (byte) 4:
            case (byte) 6:
            case (byte) 7:
                if (bArr.length == (fieldSize * 2) + 1) {
                    return createPoint(fromArray(bArr, 1, fieldSize), fromArray(bArr, fieldSize + 1, fieldSize), false);
                }
                throw new IllegalArgumentException("Incorrect length for uncompressed/hybrid encoding");
            default:
                throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(bArr[0], 16));
        }
    }

    protected abstract ECPoint decompressPoint(int i, BigInteger bigInteger);

    public abstract ECFieldElement fromBigInteger(BigInteger bigInteger);

    public ECFieldElement getA() {
        return this.f112a;
    }

    public ECFieldElement getB() {
        return this.f113b;
    }

    public abstract int getFieldSize();

    public abstract ECPoint getInfinity();
}
