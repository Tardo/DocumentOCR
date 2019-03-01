package org.spongycastle.math.ec;

import java.math.BigInteger;
import java.util.Random;

public abstract class ECCurve {
    /* renamed from: a */
    ECFieldElement f197a;
    /* renamed from: b */
    ECFieldElement f198b;

    public static class F2m extends ECCurve {
        /* renamed from: h */
        private BigInteger f429h;
        private org.spongycastle.math.ec.ECPoint.F2m infinity;
        private int k1;
        private int k2;
        private int k3;
        /* renamed from: m */
        private int f430m;
        private byte mu;
        /* renamed from: n */
        private BigInteger f431n;
        private BigInteger[] si;

        public F2m(int m, int k, BigInteger a, BigInteger b) {
            this(m, k, 0, 0, a, b, null, null);
        }

        public F2m(int m, int k, BigInteger a, BigInteger b, BigInteger n, BigInteger h) {
            this(m, k, 0, 0, a, b, n, h);
        }

        public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b) {
            this(m, k1, k2, k3, a, b, null, null);
        }

        public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, BigInteger n, BigInteger h) {
            this.mu = (byte) 0;
            this.si = null;
            this.f430m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.f431n = n;
            this.f429h = h;
            if (k1 == 0) {
                throw new IllegalArgumentException("k1 must be > 0");
            }
            if (k2 == 0) {
                if (k3 != 0) {
                    throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
                }
            } else if (k2 <= k1) {
                throw new IllegalArgumentException("k2 must be > k1");
            } else if (k3 <= k2) {
                throw new IllegalArgumentException("k3 must be > k2");
            }
            this.a = fromBigInteger(a);
            this.b = fromBigInteger(b);
            this.infinity = new org.spongycastle.math.ec.ECPoint.F2m(this, null, null);
        }

        public int getFieldSize() {
            return this.f430m;
        }

        public ECFieldElement fromBigInteger(BigInteger x) {
            return new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, x);
        }

        public ECPoint createPoint(BigInteger x, BigInteger y, boolean withCompression) {
            return new org.spongycastle.math.ec.ECPoint.F2m(this, fromBigInteger(x), fromBigInteger(y), withCompression);
        }

        public ECPoint decodePoint(byte[] encoded) {
            switch (encoded[0]) {
                case (byte) 0:
                    if (encoded.length <= 1) {
                        return getInfinity();
                    }
                    throw new RuntimeException("Invalid point encoding");
                case (byte) 2:
                case (byte) 3:
                    byte[] enc = new byte[(encoded.length - 1)];
                    System.arraycopy(encoded, 1, enc, 0, enc.length);
                    if (encoded[0] == (byte) 2) {
                        return decompressPoint(enc, 0);
                    }
                    return decompressPoint(enc, 1);
                case (byte) 4:
                case (byte) 6:
                case (byte) 7:
                    byte[] xEnc = new byte[((encoded.length - 1) / 2)];
                    byte[] yEnc = new byte[((encoded.length - 1) / 2)];
                    System.arraycopy(encoded, 1, xEnc, 0, xEnc.length);
                    System.arraycopy(encoded, xEnc.length + 1, yEnc, 0, yEnc.length);
                    return new org.spongycastle.math.ec.ECPoint.F2m(this, new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, new BigInteger(1, xEnc)), new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, new BigInteger(1, yEnc)), false);
                default:
                    throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
            }
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }

        public boolean isKoblitz() {
            return (this.f431n == null || this.f429h == null || ((!this.a.toBigInteger().equals(ECConstants.ZERO) && !this.a.toBigInteger().equals(ECConstants.ONE)) || !this.b.toBigInteger().equals(ECConstants.ONE))) ? false : true;
        }

        synchronized byte getMu() {
            if (this.mu == (byte) 0) {
                this.mu = Tnaf.getMu(this);
            }
            return this.mu;
        }

        synchronized BigInteger[] getSi() {
            if (this.si == null) {
                this.si = Tnaf.getSi(this);
            }
            return this.si;
        }

        private ECPoint decompressPoint(byte[] xEnc, int ypBit) {
            ECFieldElement yp;
            ECFieldElement xp = new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, new BigInteger(1, xEnc));
            if (xp.toBigInteger().equals(ECConstants.ZERO)) {
                yp = (org.spongycastle.math.ec.ECFieldElement.F2m) this.b;
                for (int i = 0; i < this.f430m - 1; i++) {
                    yp = yp.square();
                }
            } else {
                ECFieldElement z = solveQuadradicEquation(xp.add(this.a).add(this.b.multiply(xp.square().invert())));
                if (z == null) {
                    throw new RuntimeException("Invalid point compression");
                }
                int zBit = 0;
                if (z.toBigInteger().testBit(0)) {
                    zBit = 1;
                }
                if (zBit != ypBit) {
                    z = z.add(new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, ECConstants.ONE));
                }
                yp = xp.multiply(z);
            }
            return new org.spongycastle.math.ec.ECPoint.F2m(this, xp, yp);
        }

        private ECFieldElement solveQuadradicEquation(ECFieldElement beta) {
            ECFieldElement zeroElement = new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, ECConstants.ZERO);
            if (beta.toBigInteger().equals(ECConstants.ZERO)) {
                return zeroElement;
            }
            ECFieldElement z;
            ECFieldElement gamma = zeroElement;
            Random rand = new Random();
            do {
                ECFieldElement t = new org.spongycastle.math.ec.ECFieldElement.F2m(this.f430m, this.k1, this.k2, this.k3, new BigInteger(this.f430m, rand));
                z = zeroElement;
                ECFieldElement w = beta;
                for (int i = 1; i <= this.f430m - 1; i++) {
                    ECFieldElement w2 = w.square();
                    z = z.square().add(w2.multiply(t));
                    w = w2.add(beta);
                }
                if (!w.toBigInteger().equals(ECConstants.ZERO)) {
                    return null;
                }
            } while (z.square().add(z).toBigInteger().equals(ECConstants.ZERO));
            return z;
        }

        public boolean equals(Object anObject) {
            if (anObject == this) {
                return true;
            }
            if (!(anObject instanceof F2m)) {
                return false;
            }
            F2m other = (F2m) anObject;
            if (this.f430m == other.f430m && this.k1 == other.k1 && this.k2 == other.k2 && this.k3 == other.k3 && this.a.equals(other.a) && this.b.equals(other.b)) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            return ((((this.a.hashCode() ^ this.b.hashCode()) ^ this.f430m) ^ this.k1) ^ this.k2) ^ this.k3;
        }

        public int getM() {
            return this.f430m;
        }

        public boolean isTrinomial() {
            return this.k2 == 0 && this.k3 == 0;
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

        public BigInteger getN() {
            return this.f431n;
        }

        public BigInteger getH() {
            return this.f429h;
        }
    }

    public static class Fp extends ECCurve {
        org.spongycastle.math.ec.ECPoint.Fp infinity = new org.spongycastle.math.ec.ECPoint.Fp(this, null, null);
        /* renamed from: q */
        BigInteger f432q;

        public Fp(BigInteger q, BigInteger a, BigInteger b) {
            this.f432q = q;
            this.a = fromBigInteger(a);
            this.b = fromBigInteger(b);
        }

        public BigInteger getQ() {
            return this.f432q;
        }

        public int getFieldSize() {
            return this.f432q.bitLength();
        }

        public ECFieldElement fromBigInteger(BigInteger x) {
            return new org.spongycastle.math.ec.ECFieldElement.Fp(this.f432q, x);
        }

        public ECPoint createPoint(BigInteger x, BigInteger y, boolean withCompression) {
            return new org.spongycastle.math.ec.ECPoint.Fp(this, fromBigInteger(x), fromBigInteger(y), withCompression);
        }

        public ECPoint decodePoint(byte[] encoded) {
            int bit0 = 0;
            switch (encoded[0]) {
                case (byte) 0:
                    if (encoded.length <= 1) {
                        return getInfinity();
                    }
                    throw new RuntimeException("Invalid point encoding");
                case (byte) 2:
                case (byte) 3:
                    int ytilde = encoded[0] & 1;
                    byte[] i = new byte[(encoded.length - 1)];
                    System.arraycopy(encoded, 1, i, 0, i.length);
                    ECFieldElement x = new org.spongycastle.math.ec.ECFieldElement.Fp(this.f432q, new BigInteger(1, i));
                    ECFieldElement beta = x.multiply(x.square().add(this.a)).add(this.b).sqrt();
                    if (beta == null) {
                        throw new RuntimeException("Invalid point compression");
                    }
                    if (beta.toBigInteger().testBit(0)) {
                        bit0 = 1;
                    }
                    if (bit0 == ytilde) {
                        return new org.spongycastle.math.ec.ECPoint.Fp(this, x, beta, true);
                    }
                    return new org.spongycastle.math.ec.ECPoint.Fp(this, x, new org.spongycastle.math.ec.ECFieldElement.Fp(this.f432q, this.f432q.subtract(beta.toBigInteger())), true);
                case (byte) 4:
                case (byte) 6:
                case (byte) 7:
                    byte[] xEnc = new byte[((encoded.length - 1) / 2)];
                    byte[] yEnc = new byte[((encoded.length - 1) / 2)];
                    System.arraycopy(encoded, 1, xEnc, 0, xEnc.length);
                    System.arraycopy(encoded, xEnc.length + 1, yEnc, 0, yEnc.length);
                    return new org.spongycastle.math.ec.ECPoint.Fp(this, new org.spongycastle.math.ec.ECFieldElement.Fp(this.f432q, new BigInteger(1, xEnc)), new org.spongycastle.math.ec.ECFieldElement.Fp(this.f432q, new BigInteger(1, yEnc)));
                default:
                    throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
            }
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }

        public boolean equals(Object anObject) {
            if (anObject == this) {
                return true;
            }
            if (!(anObject instanceof Fp)) {
                return false;
            }
            Fp other = (Fp) anObject;
            if (this.f432q.equals(other.f432q) && this.a.equals(other.a) && this.b.equals(other.b)) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            return (this.a.hashCode() ^ this.b.hashCode()) ^ this.f432q.hashCode();
        }
    }

    public abstract ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2, boolean z);

    public abstract ECPoint decodePoint(byte[] bArr);

    public abstract ECFieldElement fromBigInteger(BigInteger bigInteger);

    public abstract int getFieldSize();

    public abstract ECPoint getInfinity();

    public ECFieldElement getA() {
        return this.f197a;
    }

    public ECFieldElement getB() {
        return this.f198b;
    }
}
