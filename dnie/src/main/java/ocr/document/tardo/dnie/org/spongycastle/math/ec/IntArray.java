package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.spongycastle.util.Arrays;

class IntArray {
    private int[] m_ints;

    public IntArray(int intLen) {
        this.m_ints = new int[intLen];
    }

    public IntArray(int[] ints) {
        this.m_ints = ints;
    }

    public IntArray(BigInteger bigInt) {
        this(bigInt, 0);
    }

    public IntArray(BigInteger bigInt, int minIntLen) {
        if (bigInt.signum() == -1) {
            throw new IllegalArgumentException("Only positive Integers allowed");
        }
        if (bigInt.equals(ECConstants.ZERO)) {
            this.m_ints = new int[]{0};
            return;
        }
        int barrBarrI;
        byte[] barr = bigInt.toByteArray();
        int barrLen = barr.length;
        int barrStart = 0;
        if (barr[0] == (byte) 0) {
            barrLen--;
            barrStart = 1;
        }
        int intLen = (barrLen + 3) / 4;
        if (intLen < minIntLen) {
            this.m_ints = new int[minIntLen];
        } else {
            this.m_ints = new int[intLen];
        }
        int iarrJ = intLen - 1;
        int rem = (barrLen % 4) + barrStart;
        int temp = 0;
        int barrI = barrStart;
        if (barrStart < rem) {
            while (barrI < rem) {
                temp <<= 8;
                barrBarrI = barr[barrI];
                if (barrBarrI < 0) {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
                barrI++;
            }
            int iarrJ2 = iarrJ - 1;
            this.m_ints[iarrJ] = temp;
            iarrJ = iarrJ2;
        }
        while (iarrJ >= 0) {
            temp = 0;
            int i = 0;
            int barrI2 = barrI;
            while (i < 4) {
                temp <<= 8;
                barrI = barrI2 + 1;
                barrBarrI = barr[barrI2];
                if (barrBarrI < 0) {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
                i++;
                barrI2 = barrI;
            }
            this.m_ints[iarrJ] = temp;
            iarrJ--;
            barrI = barrI2;
        }
    }

    public boolean isZero() {
        return this.m_ints.length == 0 || (this.m_ints[0] == 0 && getUsedLength() == 0);
    }

    public int getUsedLength() {
        int highestIntPos = this.m_ints.length;
        if (highestIntPos < 1) {
            return 0;
        }
        if (this.m_ints[0] != 0) {
            do {
                highestIntPos--;
            } while (this.m_ints[highestIntPos] == 0);
            return highestIntPos + 1;
        }
        do {
            highestIntPos--;
            if (this.m_ints[highestIntPos] != 0) {
                return highestIntPos + 1;
            }
        } while (highestIntPos > 0);
        return 0;
    }

    public int bitLength() {
        int intLen = getUsedLength();
        if (intLen == 0) {
            return 0;
        }
        int last = intLen - 1;
        int highest = this.m_ints[last];
        int bits = (last << 5) + 1;
        if ((-65536 & highest) != 0) {
            if ((-16777216 & highest) != 0) {
                bits += 24;
                highest >>>= 24;
            } else {
                bits += 16;
                highest >>>= 16;
            }
        } else if (highest > 255) {
            bits += 8;
            highest >>>= 8;
        }
        while (highest != 1) {
            bits++;
            highest >>>= 1;
        }
        return bits;
    }

    private int[] resizedInts(int newLen) {
        int copyLen;
        int[] newInts = new int[newLen];
        int oldLen = this.m_ints.length;
        if (oldLen < newLen) {
            copyLen = oldLen;
        } else {
            copyLen = newLen;
        }
        System.arraycopy(this.m_ints, 0, newInts, 0, copyLen);
        return newInts;
    }

    public BigInteger toBigInteger() {
        int usedLen = getUsedLength();
        if (usedLen == 0) {
            return ECConstants.ZERO;
        }
        int barrI;
        int highestInt = this.m_ints[usedLen - 1];
        byte[] temp = new byte[4];
        boolean trailingZeroBytesDone = false;
        int j = 3;
        int barrI2 = 0;
        while (j >= 0) {
            byte thisByte = (byte) (highestInt >>> (j * 8));
            if (trailingZeroBytesDone || thisByte != (byte) 0) {
                trailingZeroBytesDone = true;
                barrI = barrI2 + 1;
                temp[barrI2] = thisByte;
            } else {
                barrI = barrI2;
            }
            j--;
            barrI2 = barrI;
        }
        byte[] barr = new byte[(((usedLen - 1) * 4) + barrI2)];
        for (j = 0; j < barrI2; j++) {
            barr[j] = temp[j];
        }
        int iarrJ = usedLen - 2;
        barrI = barrI2;
        while (iarrJ >= 0) {
            j = 3;
            barrI2 = barrI;
            while (j >= 0) {
                barrI = barrI2 + 1;
                barr[barrI2] = (byte) (this.m_ints[iarrJ] >>> (j * 8));
                j--;
                barrI2 = barrI;
            }
            iarrJ--;
            barrI = barrI2;
        }
        return new BigInteger(1, barr);
    }

    public void shiftLeft() {
        int usedLen = getUsedLength();
        if (usedLen != 0) {
            if (this.m_ints[usedLen - 1] < 0) {
                usedLen++;
                if (usedLen > this.m_ints.length) {
                    this.m_ints = resizedInts(this.m_ints.length + 1);
                }
            }
            boolean carry = false;
            for (int i = 0; i < usedLen; i++) {
                boolean nextCarry = this.m_ints[i] < 0;
                int[] iArr = this.m_ints;
                iArr[i] = iArr[i] << 1;
                if (carry) {
                    iArr = this.m_ints;
                    iArr[i] = iArr[i] | 1;
                }
                carry = nextCarry;
            }
        }
    }

    public IntArray shiftLeft(int n) {
        int usedLen = getUsedLength();
        if (usedLen == 0 || n == 0) {
            return this;
        }
        if (n > 31) {
            throw new IllegalArgumentException("shiftLeft() for max 31 bits , " + n + "bit shift is not possible");
        }
        int[] newInts = new int[(usedLen + 1)];
        int nm32 = 32 - n;
        newInts[0] = this.m_ints[0] << n;
        for (int i = 1; i < usedLen; i++) {
            newInts[i] = (this.m_ints[i] << n) | (this.m_ints[i - 1] >>> nm32);
        }
        newInts[usedLen] = this.m_ints[usedLen - 1] >>> nm32;
        this(newInts);
        return this;
    }

    public void addShifted(IntArray other, int shift) {
        int usedLenOther = other.getUsedLength();
        int newMinUsedLen = usedLenOther + shift;
        if (newMinUsedLen > this.m_ints.length) {
            this.m_ints = resizedInts(newMinUsedLen);
        }
        for (int i = 0; i < usedLenOther; i++) {
            int[] iArr = this.m_ints;
            int i2 = i + shift;
            iArr[i2] = iArr[i2] ^ other.m_ints[i];
        }
    }

    public int getLength() {
        return this.m_ints.length;
    }

    public boolean testBit(int n) {
        if ((this.m_ints[n >> 5] & (1 << (n & 31))) != 0) {
            return true;
        }
        return false;
    }

    public void flipBit(int n) {
        int theInt = n >> 5;
        int flipper = 1 << (n & 31);
        int[] iArr = this.m_ints;
        iArr[theInt] = iArr[theInt] ^ flipper;
    }

    public void setBit(int n) {
        int theInt = n >> 5;
        int setter = 1 << (n & 31);
        int[] iArr = this.m_ints;
        iArr[theInt] = iArr[theInt] | setter;
    }

    public IntArray multiply(IntArray other, int m) {
        int t = (m + 31) >> 5;
        if (this.m_ints.length < t) {
            this.m_ints = resizedInts(t);
        }
        IntArray b = new IntArray(other.resizedInts(other.getLength() + 1));
        IntArray c = new IntArray(((m + m) + 31) >> 5);
        int testBit = 1;
        for (int k = 0; k < 32; k++) {
            for (int j = 0; j < t; j++) {
                if ((this.m_ints[j] & testBit) != 0) {
                    c.addShifted(b, j);
                }
            }
            testBit <<= 1;
            b.shiftLeft();
        }
        return c;
    }

    public void reduce(int m, int[] redPol) {
        for (int i = (m + m) - 2; i >= m; i--) {
            if (testBit(i)) {
                int bit = i - m;
                flipBit(bit);
                flipBit(i);
                int l = redPol.length;
                while (true) {
                    l--;
                    if (l < 0) {
                        break;
                    }
                    flipBit(redPol[l] + bit);
                }
            }
        }
        this.m_ints = resizedInts((m + 31) >> 5);
    }

    public IntArray square(int m) {
        int[] table = new int[]{0, 1, 4, 5, 16, 17, 20, 21, 64, 65, 68, 69, 80, 81, 84, 85};
        int t = (m + 31) >> 5;
        if (this.m_ints.length < t) {
            this.m_ints = resizedInts(t);
        }
        IntArray c = new IntArray(t + t);
        for (int i = 0; i < t; i++) {
            int j;
            int v0 = 0;
            for (j = 0; j < 4; j++) {
                v0 = (v0 >>> 8) | (table[(this.m_ints[i] >>> (j * 4)) & 15] << 24);
            }
            c.m_ints[i + i] = v0;
            v0 = 0;
            int upper = this.m_ints[i] >>> 16;
            for (j = 0; j < 4; j++) {
                v0 = (v0 >>> 8) | (table[(upper >>> (j * 4)) & 15] << 24);
            }
            c.m_ints[(i + i) + 1] = v0;
        }
        return c;
    }

    public boolean equals(Object o) {
        if (!(o instanceof IntArray)) {
            return false;
        }
        IntArray other = (IntArray) o;
        int usedLen = getUsedLength();
        if (other.getUsedLength() != usedLen) {
            return false;
        }
        for (int i = 0; i < usedLen; i++) {
            if (this.m_ints[i] != other.m_ints[i]) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        int hash = 1;
        for (int i = 0; i < getUsedLength(); i++) {
            hash = (hash * 31) + this.m_ints[i];
        }
        return hash;
    }

    public Object clone() {
        return new IntArray(Arrays.clone(this.m_ints));
    }

    public String toString() {
        int usedLen = getUsedLength();
        if (usedLen == 0) {
            return "0";
        }
        StringBuffer sb = new StringBuffer(Integer.toBinaryString(this.m_ints[usedLen - 1]));
        for (int iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--) {
            String hexString = Integer.toBinaryString(this.m_ints[iarrJ]);
            for (int i = hexString.length(); i < 8; i++) {
                hexString = "0" + hexString;
            }
            sb.append(hexString);
        }
        return sb.toString();
    }
}
