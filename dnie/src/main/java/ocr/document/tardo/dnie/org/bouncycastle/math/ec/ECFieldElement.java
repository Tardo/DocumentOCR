package org.bouncycastle.math.ec;

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
        private int f517m;
        private int representation;
        /* renamed from: t */
        private int f518t;
        /* renamed from: x */
        private IntArray f519x;

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger) {
            this.f518t = (i + 31) >> 5;
            this.f519x = new IntArray(bigInteger, this.f518t);
            if (i3 == 0 && i4 == 0) {
                this.representation = 2;
            } else if (i3 >= i4) {
                throw new IllegalArgumentException("k2 must be smaller than k3");
            } else if (i3 <= 0) {
                throw new IllegalArgumentException("k2 must be larger than 0");
            } else {
                this.representation = 3;
            }
            if (bigInteger.signum() < 0) {
                throw new IllegalArgumentException("x value cannot be negative");
            }
            this.f517m = i;
            this.k1 = i2;
            this.k2 = i3;
            this.k3 = i4;
        }

        private F2m(int i, int i2, int i3, int i4, IntArray intArray) {
            this.f518t = (i + 31) >> 5;
            this.f519x = intArray;
            this.f517m = i;
            this.k1 = i2;
            this.k2 = i3;
            this.k3 = i4;
            if (i3 == 0 && i4 == 0) {
                this.representation = 2;
            } else {
                this.representation = 3;
            }
        }

        public F2m(int i, int i2, BigInteger bigInteger) {
            this(i, i2, 0, 0, bigInteger);
        }

        public static void checkFieldElements(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            if ((eCFieldElement instanceof F2m) && (eCFieldElement2 instanceof F2m)) {
                F2m f2m = (F2m) eCFieldElement;
                F2m f2m2 = (F2m) eCFieldElement2;
                if (f2m.f517m != f2m2.f517m || f2m.k1 != f2m2.k1 || f2m.k2 != f2m2.k2 || f2m.k3 != f2m2.k3) {
                    throw new IllegalArgumentException("Field elements are not elements of the same field F2m");
                } else if (f2m.representation != f2m2.representation) {
                    throw new IllegalArgumentException("One of the field elements are not elements has incorrect representation");
                } else {
                    return;
                }
            }
            throw new IllegalArgumentException("Field elements are not both instances of ECFieldElement.F2m");
        }

        public ECFieldElement add(ECFieldElement eCFieldElement) {
            IntArray intArray = (IntArray) this.f519x.clone();
            intArray.addShifted(((F2m) eCFieldElement).f519x, 0);
            return new F2m(this.f517m, this.k1, this.k2, this.k3, intArray);
        }

        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return multiply(eCFieldElement.invert());
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof F2m)) {
                return false;
            }
            F2m f2m = (F2m) obj;
            return this.f517m == f2m.f517m && this.k1 == f2m.k1 && this.k2 == f2m.k2 && this.k3 == f2m.k3 && this.representation == f2m.representation && this.f519x.equals(f2m.f519x);
        }

        public String getFieldName() {
            return "F2m";
        }

        public int getFieldSize() {
            return this.f517m;
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
            return this.f517m;
        }

        public int getRepresentation() {
            return this.representation;
        }

        public int hashCode() {
            return (((this.f519x.hashCode() ^ this.f517m) ^ this.k1) ^ this.k2) ^ this.k3;
        }

        public ECFieldElement invert() {
            IntArray intArray = (IntArray) this.f519x.clone();
            IntArray intArray2 = new IntArray(this.f518t);
            intArray2.setBit(this.f517m);
            intArray2.setBit(0);
            intArray2.setBit(this.k1);
            if (this.representation == 3) {
                intArray2.setBit(this.k2);
                intArray2.setBit(this.k3);
            }
            IntArray intArray3 = new IntArray(this.f518t);
            intArray3.setBit(0);
            IntArray intArray4 = new IntArray(this.f518t);
            IntArray intArray5 = intArray3;
            intArray3 = intArray2;
            intArray2 = intArray;
            intArray = intArray5;
            while (!intArray2.isZero()) {
                int bitLength = intArray2.bitLength() - intArray3.bitLength();
                if (bitLength < 0) {
                    bitLength = -bitLength;
                    intArray5 = intArray;
                    intArray = intArray4;
                    intArray4 = intArray5;
                    IntArray intArray6 = intArray2;
                    intArray2 = intArray3;
                    intArray3 = intArray6;
                }
                int i = bitLength >> 5;
                bitLength &= 31;
                intArray2.addShifted(intArray3.shiftLeft(bitLength), i);
                intArray.addShifted(intArray4.shiftLeft(bitLength), i);
            }
            return new F2m(this.f517m, this.k1, this.k2, this.k3, intArray4);
        }

        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            IntArray multiply = this.f519x.multiply(((F2m) eCFieldElement).f519x, this.f517m);
            multiply.reduce(this.f517m, new int[]{this.k1, this.k2, this.k3});
            return new F2m(this.f517m, this.k1, this.k2, this.k3, multiply);
        }

        public ECFieldElement negate() {
            return this;
        }

        public ECFieldElement sqrt() {
            throw new RuntimeException("Not implemented");
        }

        public ECFieldElement square() {
            IntArray square = this.f519x.square(this.f517m);
            square.reduce(this.f517m, new int[]{this.k1, this.k2, this.k3});
            return new F2m(this.f517m, this.k1, this.k2, this.k3, square);
        }

        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return add(eCFieldElement);
        }

        public BigInteger toBigInteger() {
            return this.f519x.toBigInteger();
        }
    }

    public static class Fp extends ECFieldElement {
        /* renamed from: q */
        BigInteger f520q;
        /* renamed from: x */
        BigInteger f521x;

        public Fp(BigInteger bigInteger, BigInteger bigInteger2) {
            this.f521x = bigInteger2;
            if (bigInteger2.compareTo(bigInteger) >= 0) {
                throw new IllegalArgumentException("x value too large in field element");
            }
            this.f520q = bigInteger;
        }

        private static BigInteger[] lucasSequence(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            int bitLength = bigInteger4.bitLength();
            int lowestSetBit = bigInteger4.getLowestSetBit();
            BigInteger bigInteger5 = ECConstants.ONE;
            BigInteger bigInteger6 = ECConstants.TWO;
            BigInteger bigInteger7 = ECConstants.ONE;
            int i = bitLength - 1;
            BigInteger bigInteger8 = bigInteger2;
            BigInteger bigInteger9 = bigInteger6;
            BigInteger bigInteger10 = ECConstants.ONE;
            BigInteger bigInteger11 = bigInteger7;
            while (i >= lowestSetBit + 1) {
                bigInteger11 = bigInteger11.multiply(bigInteger10).mod(bigInteger);
                if (bigInteger4.testBit(i)) {
                    bigInteger10 = bigInteger11.multiply(bigInteger3).mod(bigInteger);
                    bigInteger5 = bigInteger5.multiply(bigInteger8).mod(bigInteger);
                    bigInteger6 = bigInteger8.multiply(bigInteger9).subtract(bigInteger2.multiply(bigInteger11)).mod(bigInteger);
                    bigInteger7 = bigInteger8.multiply(bigInteger8).subtract(bigInteger10.shiftLeft(1)).mod(bigInteger);
                } else {
                    bigInteger6 = bigInteger5.multiply(bigInteger9).subtract(bigInteger11).mod(bigInteger);
                    bigInteger10 = bigInteger8.multiply(bigInteger9).subtract(bigInteger2.multiply(bigInteger11)).mod(bigInteger);
                    bigInteger5 = bigInteger6;
                    bigInteger6 = bigInteger9.multiply(bigInteger9).subtract(bigInteger11.shiftLeft(1)).mod(bigInteger);
                    bigInteger7 = bigInteger10;
                    bigInteger10 = bigInteger11;
                }
                i--;
                bigInteger8 = bigInteger7;
                bigInteger9 = bigInteger6;
            }
            bigInteger10 = bigInteger11.multiply(bigInteger10).mod(bigInteger);
            bigInteger6 = bigInteger10.multiply(bigInteger3).mod(bigInteger);
            bigInteger7 = bigInteger5.multiply(bigInteger9).subtract(bigInteger10).mod(bigInteger);
            bigInteger6 = bigInteger7;
            bigInteger7 = bigInteger8.multiply(bigInteger9).subtract(bigInteger2.multiply(bigInteger10)).mod(bigInteger);
            bigInteger11 = bigInteger10.multiply(bigInteger6).mod(bigInteger);
            for (bitLength = 1; bitLength <= lowestSetBit; bitLength++) {
                bigInteger6 = bigInteger6.multiply(bigInteger7).mod(bigInteger);
                bigInteger7 = bigInteger7.multiply(bigInteger7).subtract(bigInteger11.shiftLeft(1)).mod(bigInteger);
                bigInteger11 = bigInteger11.multiply(bigInteger11).mod(bigInteger);
            }
            return new BigInteger[]{bigInteger6, bigInteger7};
        }

        public ECFieldElement add(ECFieldElement eCFieldElement) {
            return new Fp(this.f520q, this.f521x.add(eCFieldElement.toBigInteger()).mod(this.f520q));
        }

        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return new Fp(this.f520q, this.f521x.multiply(eCFieldElement.toBigInteger().modInverse(this.f520q)).mod(this.f520q));
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof Fp)) {
                return false;
            }
            Fp fp = (Fp) obj;
            return this.f520q.equals(fp.f520q) && this.f521x.equals(fp.f521x);
        }

        public String getFieldName() {
            return "Fp";
        }

        public int getFieldSize() {
            return this.f520q.bitLength();
        }

        public BigInteger getQ() {
            return this.f520q;
        }

        public int hashCode() {
            return this.f520q.hashCode() ^ this.f521x.hashCode();
        }

        public ECFieldElement invert() {
            return new Fp(this.f520q, this.f521x.modInverse(this.f520q));
        }

        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            return new Fp(this.f520q, this.f521x.multiply(eCFieldElement.toBigInteger()).mod(this.f520q));
        }

        public ECFieldElement negate() {
            return new Fp(this.f520q, this.f521x.negate().mod(this.f520q));
        }

        public ECFieldElement sqrt() {
            if (!this.f520q.testBit(0)) {
                throw new RuntimeException("not done yet");
            } else if (this.f520q.testBit(1)) {
                ECFieldElement fp = new Fp(this.f520q, this.f521x.modPow(this.f520q.shiftRight(2).add(ECConstants.ONE), this.f520q));
                if (!fp.square().equals(this)) {
                    fp = null;
                }
                return fp;
            } else {
                BigInteger subtract = this.f520q.subtract(ECConstants.ONE);
                BigInteger shiftRight = subtract.shiftRight(1);
                if (!this.f521x.modPow(shiftRight, this.f520q).equals(ECConstants.ONE)) {
                    return null;
                }
                BigInteger bigInteger;
                BigInteger add = subtract.shiftRight(2).shiftLeft(1).add(ECConstants.ONE);
                BigInteger bigInteger2 = this.f521x;
                BigInteger mod = bigInteger2.shiftLeft(2).mod(this.f520q);
                Random random = new Random();
                while (true) {
                    bigInteger = new BigInteger(this.f520q.bitLength(), random);
                    if (bigInteger.compareTo(this.f520q) < 0 && bigInteger.multiply(bigInteger).subtract(mod).modPow(shiftRight, this.f520q).equals(subtract)) {
                        BigInteger[] lucasSequence = lucasSequence(this.f520q, bigInteger, bigInteger2, add);
                        BigInteger bigInteger3 = lucasSequence[0];
                        bigInteger = lucasSequence[1];
                        if (bigInteger.multiply(bigInteger).mod(this.f520q).equals(mod)) {
                            break;
                        } else if (!(bigInteger3.equals(ECConstants.ONE) || bigInteger3.equals(subtract))) {
                            return null;
                        }
                    }
                }
                if (bigInteger.testBit(0)) {
                    bigInteger = bigInteger.add(this.f520q);
                }
                return new Fp(this.f520q, bigInteger.shiftRight(1));
            }
        }

        public ECFieldElement square() {
            return new Fp(this.f520q, this.f521x.multiply(this.f521x).mod(this.f520q));
        }

        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return new Fp(this.f520q, this.f521x.subtract(eCFieldElement.toBigInteger()).mod(this.f520q));
        }

        public BigInteger toBigInteger() {
            return this.f521x;
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
