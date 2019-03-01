package org.spongycastle.math.ec;

import java.math.BigInteger;
import java.util.Random;

public abstract class ECFieldElement implements ECConstants {

    public static class F2m extends ECFieldElement {
        public static final int GNB = 1;
        public static final int PPB = 3;
        public static final int TPB = 2;
        private int k1;
        private int k2;
        private int k3;
        /* renamed from: m */
        private int f594m;
        private int representation;
        /* renamed from: t */
        private int f595t;
        /* renamed from: x */
        private IntArray f596x;

        public F2m(int m, int k1, int k2, int k3, BigInteger x) {
            this.f595t = (m + 31) >> 5;
            this.f596x = new IntArray(x, this.f595t);
            if (k2 == 0 && k3 == 0) {
                this.representation = 2;
            } else if (k2 >= k3) {
                throw new IllegalArgumentException("k2 must be smaller than k3");
            } else if (k2 <= 0) {
                throw new IllegalArgumentException("k2 must be larger than 0");
            } else {
                this.representation = 3;
            }
            if (x.signum() < 0) {
                throw new IllegalArgumentException("x value cannot be negative");
            }
            this.f594m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
        }

        public F2m(int m, int k, BigInteger x) {
            this(m, k, 0, 0, x);
        }

        private F2m(int m, int k1, int k2, int k3, IntArray x) {
            this.f595t = (m + 31) >> 5;
            this.f596x = x;
            this.f594m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            if (k2 == 0 && k3 == 0) {
                this.representation = 2;
            } else {
                this.representation = 3;
            }
        }

        public BigInteger toBigInteger() {
            return this.f596x.toBigInteger();
        }

        public String getFieldName() {
            return "F2m";
        }

        public int getFieldSize() {
            return this.f594m;
        }

        public static void checkFieldElements(ECFieldElement a, ECFieldElement b) {
            if ((a instanceof F2m) && (b instanceof F2m)) {
                F2m aF2m = (F2m) a;
                F2m bF2m = (F2m) b;
                if (aF2m.f594m != bF2m.f594m || aF2m.k1 != bF2m.k1 || aF2m.k2 != bF2m.k2 || aF2m.k3 != bF2m.k3) {
                    throw new IllegalArgumentException("Field elements are not elements of the same field F2m");
                } else if (aF2m.representation != bF2m.representation) {
                    throw new IllegalArgumentException("One of the field elements are not elements has incorrect representation");
                } else {
                    return;
                }
            }
            throw new IllegalArgumentException("Field elements are not both instances of ECFieldElement.F2m");
        }

        public ECFieldElement add(ECFieldElement b) {
            IntArray iarrClone = (IntArray) this.f596x.clone();
            iarrClone.addShifted(((F2m) b).f596x, 0);
            return new F2m(this.f594m, this.k1, this.k2, this.k3, iarrClone);
        }

        public ECFieldElement subtract(ECFieldElement b) {
            return add(b);
        }

        public ECFieldElement multiply(ECFieldElement b) {
            IntArray mult = this.f596x.multiply(((F2m) b).f596x, this.f594m);
            mult.reduce(this.f594m, new int[]{this.k1, this.k2, this.k3});
            return new F2m(this.f594m, this.k1, this.k2, this.k3, mult);
        }

        public ECFieldElement divide(ECFieldElement b) {
            return multiply(b.invert());
        }

        public ECFieldElement negate() {
            return this;
        }

        public ECFieldElement square() {
            IntArray squared = this.f596x.square(this.f594m);
            squared.reduce(this.f594m, new int[]{this.k1, this.k2, this.k3});
            return new F2m(this.f594m, this.k1, this.k2, this.k3, squared);
        }

        public ECFieldElement invert() {
            IntArray uz = (IntArray) this.f596x.clone();
            IntArray vz = new IntArray(this.f595t);
            vz.setBit(this.f594m);
            vz.setBit(0);
            vz.setBit(this.k1);
            if (this.representation == 3) {
                vz.setBit(this.k2);
                vz.setBit(this.k3);
            }
            IntArray g1z = new IntArray(this.f595t);
            g1z.setBit(0);
            IntArray g2z = new IntArray(this.f595t);
            while (!uz.isZero()) {
                int j = uz.bitLength() - vz.bitLength();
                if (j < 0) {
                    IntArray uzCopy = uz;
                    uz = vz;
                    vz = uzCopy;
                    IntArray g1zCopy = g1z;
                    g1z = g2z;
                    g2z = g1zCopy;
                    j = -j;
                }
                int jInt = j >> 5;
                int jBit = j & 31;
                uz.addShifted(vz.shiftLeft(jBit), jInt);
                g1z.addShifted(g2z.shiftLeft(jBit), jInt);
            }
            return new F2m(this.f594m, this.k1, this.k2, this.k3, g2z);
        }

        public ECFieldElement sqrt() {
            throw new RuntimeException("Not implemented");
        }

        public int getRepresentation() {
            return this.representation;
        }

        public int getM() {
            return this.f594m;
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

        public boolean equals(Object anObject) {
            if (anObject == this) {
                return true;
            }
            if (!(anObject instanceof F2m)) {
                return false;
            }
            F2m b = (F2m) anObject;
            if (this.f594m == b.f594m && this.k1 == b.k1 && this.k2 == b.k2 && this.k3 == b.k3 && this.representation == b.representation && this.f596x.equals(b.f596x)) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            return (((this.f596x.hashCode() ^ this.f594m) ^ this.k1) ^ this.k2) ^ this.k3;
        }
    }

    public static class Fp extends ECFieldElement {
        /* renamed from: q */
        BigInteger f597q;
        /* renamed from: x */
        BigInteger f598x;

        public Fp(BigInteger q, BigInteger x) {
            this.f598x = x;
            if (x.compareTo(q) >= 0) {
                throw new IllegalArgumentException("x value too large in field element");
            }
            this.f597q = q;
        }

        public BigInteger toBigInteger() {
            return this.f598x;
        }

        public String getFieldName() {
            return "Fp";
        }

        public int getFieldSize() {
            return this.f597q.bitLength();
        }

        public BigInteger getQ() {
            return this.f597q;
        }

        public ECFieldElement add(ECFieldElement b) {
            return new Fp(this.f597q, this.f598x.add(b.toBigInteger()).mod(this.f597q));
        }

        public ECFieldElement subtract(ECFieldElement b) {
            return new Fp(this.f597q, this.f598x.subtract(b.toBigInteger()).mod(this.f597q));
        }

        public ECFieldElement multiply(ECFieldElement b) {
            return new Fp(this.f597q, this.f598x.multiply(b.toBigInteger()).mod(this.f597q));
        }

        public ECFieldElement divide(ECFieldElement b) {
            return new Fp(this.f597q, this.f598x.multiply(b.toBigInteger().modInverse(this.f597q)).mod(this.f597q));
        }

        public ECFieldElement negate() {
            return new Fp(this.f597q, this.f598x.negate().mod(this.f597q));
        }

        public ECFieldElement square() {
            return new Fp(this.f597q, this.f598x.multiply(this.f598x).mod(this.f597q));
        }

        public ECFieldElement invert() {
            return new Fp(this.f597q, this.f598x.modInverse(this.f597q));
        }

        public ECFieldElement sqrt() {
            if (!this.f597q.testBit(0)) {
                throw new RuntimeException("not done yet");
            } else if (this.f597q.testBit(1)) {
                ECFieldElement z = new Fp(this.f597q, this.f598x.modPow(this.f597q.shiftRight(2).add(ECConstants.ONE), this.f597q));
                if (z.square().equals(this)) {
                    return z;
                }
                return null;
            } else {
                BigInteger qMinusOne = this.f597q.subtract(ECConstants.ONE);
                BigInteger legendreExponent = qMinusOne.shiftRight(1);
                if (!this.f598x.modPow(legendreExponent, this.f597q).equals(ECConstants.ONE)) {
                    return null;
                }
                BigInteger V;
                BigInteger k = qMinusOne.shiftRight(2).shiftLeft(1).add(ECConstants.ONE);
                BigInteger Q = this.f598x;
                BigInteger fourQ = Q.shiftLeft(2).mod(this.f597q);
                Random rand = new Random();
                while (true) {
                    BigInteger P = new BigInteger(this.f597q.bitLength(), rand);
                    if (P.compareTo(this.f597q) < 0 && P.multiply(P).subtract(fourQ).modPow(legendreExponent, this.f597q).equals(qMinusOne)) {
                        BigInteger[] result = lucasSequence(this.f597q, P, Q, k);
                        BigInteger U = result[0];
                        V = result[1];
                        if (V.multiply(V).mod(this.f597q).equals(fourQ)) {
                            break;
                        } else if (!(U.equals(ECConstants.ONE) || U.equals(qMinusOne))) {
                            return null;
                        }
                    }
                }
                if (V.testBit(0)) {
                    V = V.add(this.f597q);
                }
                return new Fp(this.f597q, V.shiftRight(1));
            }
        }

        private static BigInteger[] lucasSequence(BigInteger p, BigInteger P, BigInteger Q, BigInteger k) {
            int j;
            int n = k.bitLength();
            int s = k.getLowestSetBit();
            BigInteger Uh = ECConstants.ONE;
            BigInteger Vl = ECConstants.TWO;
            BigInteger Vh = P;
            BigInteger Ql = ECConstants.ONE;
            BigInteger Qh = ECConstants.ONE;
            for (j = n - 1; j >= s + 1; j--) {
                Ql = Ql.multiply(Qh).mod(p);
                if (k.testBit(j)) {
                    Qh = Ql.multiply(Q).mod(p);
                    Uh = Uh.multiply(Vh).mod(p);
                    Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                    Vh = Vh.multiply(Vh).subtract(Qh.shiftLeft(1)).mod(p);
                } else {
                    Qh = Ql;
                    Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
                    Vh = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                    Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
                }
            }
            Ql = Ql.multiply(Qh).mod(p);
            Qh = Ql.multiply(Q).mod(p);
            Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
            Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
            Ql = Ql.multiply(Qh).mod(p);
            for (j = 1; j <= s; j++) {
                Uh = Uh.multiply(Vl).mod(p);
                Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
                Ql = Ql.multiply(Ql).mod(p);
            }
            return new BigInteger[]{Uh, Vl};
        }

        public boolean equals(Object other) {
            if (other == this) {
                return true;
            }
            if (!(other instanceof Fp)) {
                return false;
            }
            Fp o = (Fp) other;
            if (this.f597q.equals(o.f597q) && this.f598x.equals(o.f598x)) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            return this.f597q.hashCode() ^ this.f598x.hashCode();
        }
    }

    public abstract ECFieldElement add(ECFieldElement eCFieldElement);

    public abstract ECFieldElement divide(ECFieldElement eCFieldElement);

    public abstract String getFieldName();

    public abstract int getFieldSize();

    public abstract ECFieldElement invert();

    public abstract ECFieldElement multiply(ECFieldElement eCFieldElement);

    public abstract ECFieldElement negate();

    public abstract ECFieldElement sqrt();

    public abstract ECFieldElement square();

    public abstract ECFieldElement subtract(ECFieldElement eCFieldElement);

    public abstract BigInteger toBigInteger();

    public String toString() {
        return toBigInteger().toString(2);
    }
}
