package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BigIntegers {
    private static final int MAX_ITERATIONS = 1000;
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    public static byte[] asUnsignedByteArray(int i, BigInteger bigInteger) {
        Object toByteArray = bigInteger.toByteArray();
        Object obj;
        if (toByteArray[0] == (byte) 0) {
            if (toByteArray.length - 1 > i) {
                throw new IllegalArgumentException("standard length exceeded for value");
            }
            obj = new byte[i];
            System.arraycopy(toByteArray, 1, obj, obj.length - (toByteArray.length - 1), toByteArray.length - 1);
            return obj;
        } else if (toByteArray.length == i) {
            return toByteArray;
        } else {
            if (toByteArray.length > i) {
                throw new IllegalArgumentException("standard length exceeded for value");
            }
            obj = new byte[i];
            System.arraycopy(toByteArray, 0, obj, obj.length - toByteArray.length, toByteArray.length);
            return obj;
        }
    }

    public static byte[] asUnsignedByteArray(BigInteger bigInteger) {
        Object toByteArray = bigInteger.toByteArray();
        if (toByteArray[0] != (byte) 0) {
            return toByteArray;
        }
        Object obj = new byte[(toByteArray.length - 1)];
        System.arraycopy(toByteArray, 1, obj, 0, obj.length);
        return obj;
    }

    public static BigInteger createRandomInRange(BigInteger bigInteger, BigInteger bigInteger2, SecureRandom secureRandom) {
        int compareTo = bigInteger.compareTo(bigInteger2);
        if (compareTo >= 0) {
            if (compareTo <= 0) {
                return bigInteger;
            }
            throw new IllegalArgumentException("'min' may not be greater than 'max'");
        } else if (bigInteger.bitLength() > bigInteger2.bitLength() / 2) {
            return createRandomInRange(ZERO, bigInteger2.subtract(bigInteger), secureRandom).add(bigInteger);
        } else {
            for (int i = 0; i < MAX_ITERATIONS; i++) {
                BigInteger bigInteger3 = new BigInteger(bigInteger2.bitLength(), secureRandom);
                if (bigInteger3.compareTo(bigInteger) >= 0 && bigInteger3.compareTo(bigInteger2) <= 0) {
                    return bigInteger3;
                }
            }
            return new BigInteger(bigInteger2.subtract(bigInteger).bitLength() - 1, secureRandom).add(bigInteger);
        }
    }
}
