package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Vector;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.crypto.tls.CipherSuite;

public class NaccacheSternKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static int[] smallPrimes = new int[]{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, EACTags.CARDHOLDER_RELATIVE_DATA, 103, 107, 109, 113, CertificateBody.profileType, 131, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA, 139, 149, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557};
    private NaccacheSternKeyGenerationParameters param;

    private static Vector findFirstPrimes(int i) {
        Vector vector = new Vector(i);
        for (int i2 = 0; i2 != i; i2++) {
            vector.addElement(BigInteger.valueOf((long) smallPrimes[i2]));
        }
        return vector;
    }

    private static BigInteger generatePrime(int i, int i2, SecureRandom secureRandom) {
        BigInteger bigInteger = new BigInteger(i, i2, secureRandom);
        while (bigInteger.bitLength() != i) {
            bigInteger = new BigInteger(i, i2, secureRandom);
        }
        return bigInteger;
    }

    private static int getInt(SecureRandom secureRandom, int i) {
        if (((-i) & i) == i) {
            return (int) ((((long) i) * ((long) (secureRandom.nextInt() & Integer.MAX_VALUE))) >> 31);
        }
        int i2;
        int nextInt;
        do {
            nextInt = secureRandom.nextInt() & Integer.MAX_VALUE;
            i2 = nextInt % i;
        } while ((nextInt - i2) + (i - 1) < 0);
        return i2;
    }

    private static Vector permuteList(Vector vector, SecureRandom secureRandom) {
        Vector vector2 = new Vector();
        Vector vector3 = new Vector();
        for (int i = 0; i < vector.size(); i++) {
            vector3.addElement(vector.elementAt(i));
        }
        vector2.addElement(vector3.elementAt(0));
        vector3.removeElementAt(0);
        while (vector3.size() != 0) {
            vector2.insertElementAt(vector3.elementAt(0), getInt(secureRandom, vector2.size() + 1));
            vector3.removeElementAt(0);
        }
        return vector2;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        int i;
        BigInteger add;
        BigInteger add2;
        int strength = this.param.getStrength();
        Random random = this.param.getRandom();
        int certainty = this.param.getCertainty();
        boolean isDebug = this.param.isDebug();
        if (isDebug) {
            System.out.println("Fetching first " + this.param.getCntSmallPrimes() + " primes.");
        }
        Vector permuteList = permuteList(findFirstPrimes(this.param.getCntSmallPrimes()), random);
        BigInteger bigInteger = ONE;
        BigInteger bigInteger2 = ONE;
        BigInteger bigInteger3 = bigInteger;
        for (i = 0; i < permuteList.size() / 2; i++) {
            bigInteger3 = bigInteger3.multiply((BigInteger) permuteList.elementAt(i));
        }
        for (i = permuteList.size() / 2; i < permuteList.size(); i++) {
            bigInteger2 = bigInteger2.multiply((BigInteger) permuteList.elementAt(i));
        }
        BigInteger multiply = bigInteger3.multiply(bigInteger2);
        int bitLength = (strength - multiply.bitLength()) - 48;
        BigInteger generatePrime = generatePrime((bitLength / 2) + 1, certainty, random);
        BigInteger generatePrime2 = generatePrime((bitLength / 2) + 1, certainty, random);
        long j = 0;
        if (isDebug) {
            System.out.println("generating p and q");
        }
        bigInteger3 = generatePrime.multiply(bigInteger3).shiftLeft(1);
        bigInteger2 = generatePrime2.multiply(bigInteger2).shiftLeft(1);
        while (true) {
            BigInteger generatePrime3;
            j++;
            BigInteger generatePrime4 = generatePrime(24, certainty, random);
            add = generatePrime4.multiply(bigInteger3).add(ONE);
            if (add.isProbablePrime(certainty)) {
                while (true) {
                    generatePrime3 = generatePrime(24, certainty, random);
                    if (!generatePrime4.equals(generatePrime3)) {
                        add2 = generatePrime3.multiply(bigInteger2).add(ONE);
                        if (add2.isProbablePrime(certainty)) {
                            break;
                        }
                    }
                }
                if (multiply.gcd(generatePrime4.multiply(generatePrime3)).equals(ONE)) {
                    if (add.multiply(add2).bitLength() >= strength) {
                        break;
                    } else if (isDebug) {
                        System.out.println("key size too small. Should be " + strength + " but is actually " + add.multiply(add2).bitLength());
                    }
                } else {
                    continue;
                }
            }
        }
        if (isDebug) {
            System.out.println("needed " + j + " tries to generate p and q.");
        }
        bigInteger3 = add.multiply(add2);
        BigInteger multiply2 = add.subtract(ONE).multiply(add2.subtract(ONE));
        j = 0;
        if (isDebug) {
            System.out.println("generating g");
        }
        while (true) {
            Object obj;
            Vector vector = new Vector();
            long j2 = j;
            for (i = 0; i != permuteList.size(); i++) {
                BigInteger divide = multiply2.divide((BigInteger) permuteList.elementAt(i));
                do {
                    j2++;
                    bigInteger2 = new BigInteger(strength, certainty, random);
                } while (bigInteger2.modPow(divide, bigInteger3).equals(ONE));
                vector.addElement(bigInteger2);
            }
            bigInteger = ONE;
            for (int i2 = 0; i2 < permuteList.size(); i2++) {
                bigInteger = bigInteger.multiply(((BigInteger) vector.elementAt(i2)).modPow(multiply.divide((BigInteger) permuteList.elementAt(i2)), bigInteger3)).mod(bigInteger3);
            }
            int i3 = 0;
            while (i3 < permuteList.size()) {
                if (bigInteger.modPow(multiply2.divide((BigInteger) permuteList.elementAt(i3)), bigInteger3).equals(ONE)) {
                    if (isDebug) {
                        System.out.println("g has order phi(n)/" + permuteList.elementAt(i3) + "\n g: " + bigInteger);
                    }
                    obj = 1;
                    if (obj == null) {
                        j = j2;
                    } else {
                        if (bigInteger.modPow(multiply2.divide(BigInteger.valueOf(4)), bigInteger3).equals(ONE)) {
                            if (bigInteger.modPow(multiply2.divide(generatePrime4), bigInteger3).equals(ONE)) {
                                if (bigInteger.modPow(multiply2.divide(generatePrime3), bigInteger3).equals(ONE)) {
                                    if (bigInteger.modPow(multiply2.divide(generatePrime), bigInteger3).equals(ONE)) {
                                        if (bigInteger.modPow(multiply2.divide(generatePrime2), bigInteger3).equals(ONE)) {
                                            break;
                                        } else if (isDebug) {
                                            System.out.println("g has order phi(n)/b\n g: " + bigInteger);
                                            j = j2;
                                        }
                                    } else if (isDebug) {
                                        System.out.println("g has order phi(n)/a\n g: " + bigInteger);
                                        j = j2;
                                    }
                                } else if (isDebug) {
                                    System.out.println("g has order phi(n)/q'\n g: " + bigInteger);
                                    j = j2;
                                }
                            } else if (isDebug) {
                                System.out.println("g has order phi(n)/p'\n g: " + bigInteger);
                                j = j2;
                            }
                        } else if (isDebug) {
                            System.out.println("g has order phi(n)/4\n g:" + bigInteger);
                            j = j2;
                        }
                        j = j2;
                    }
                } else {
                    i3++;
                }
            }
            obj = null;
            if (obj == null) {
                if (bigInteger.modPow(multiply2.divide(BigInteger.valueOf(4)), bigInteger3).equals(ONE)) {
                    if (bigInteger.modPow(multiply2.divide(generatePrime4), bigInteger3).equals(ONE)) {
                        if (bigInteger.modPow(multiply2.divide(generatePrime3), bigInteger3).equals(ONE)) {
                            if (bigInteger.modPow(multiply2.divide(generatePrime), bigInteger3).equals(ONE)) {
                                if (bigInteger.modPow(multiply2.divide(generatePrime2), bigInteger3).equals(ONE)) {
                                    break;
                                } else if (isDebug) {
                                    System.out.println("g has order phi(n)/b\n g: " + bigInteger);
                                    j = j2;
                                }
                            } else if (isDebug) {
                                System.out.println("g has order phi(n)/a\n g: " + bigInteger);
                                j = j2;
                            }
                        } else if (isDebug) {
                            System.out.println("g has order phi(n)/q'\n g: " + bigInteger);
                            j = j2;
                        }
                    } else if (isDebug) {
                        System.out.println("g has order phi(n)/p'\n g: " + bigInteger);
                        j = j2;
                    }
                } else if (isDebug) {
                    System.out.println("g has order phi(n)/4\n g:" + bigInteger);
                    j = j2;
                }
                j = j2;
            } else {
                j = j2;
            }
        }
        if (isDebug) {
            System.out.println("needed " + j2 + " tries to generate g");
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + permuteList);
            System.out.println("sigma:...... " + multiply + " (" + multiply.bitLength() + " bits)");
            System.out.println("a:.......... " + generatePrime);
            System.out.println("b:.......... " + generatePrime2);
            System.out.println("p':......... " + generatePrime4);
            System.out.println("q':......... " + generatePrime3);
            System.out.println("p:.......... " + add);
            System.out.println("q:.......... " + add2);
            System.out.println("n:.......... " + bigInteger3);
            System.out.println("phi(n):..... " + multiply2);
            System.out.println("g:.......... " + bigInteger);
            System.out.println();
        }
        return new AsymmetricCipherKeyPair(new NaccacheSternKeyParameters(false, bigInteger, bigInteger3, multiply.bitLength()), new NaccacheSternPrivateKeyParameters(bigInteger, bigInteger3, multiply.bitLength(), permuteList, multiply2));
    }

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (NaccacheSternKeyGenerationParameters) keyGenerationParameters;
    }
}
