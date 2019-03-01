package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

public class RSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private RSAKeyGenerationParameters param;

    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger multiply;
        BigInteger bigInteger3;
        int strength = this.param.getStrength();
        int i = (strength + 1) / 2;
        int i2 = strength - i;
        int i3 = strength / 3;
        BigInteger publicExponent = this.param.getPublicExponent();
        while (true) {
            bigInteger = new BigInteger(i, 1, this.param.getRandom());
            if (!bigInteger.mod(publicExponent).equals(ONE) && bigInteger.isProbablePrime(this.param.getCertainty()) && publicExponent.gcd(bigInteger.subtract(ONE)).equals(ONE)) {
                break;
            }
        }
        while (true) {
            bigInteger2 = new BigInteger(i2, 1, this.param.getRandom());
            if (bigInteger2.subtract(bigInteger).abs().bitLength() >= i3 && !bigInteger2.mod(publicExponent).equals(ONE) && bigInteger2.isProbablePrime(this.param.getCertainty()) && publicExponent.gcd(bigInteger2.subtract(ONE)).equals(ONE)) {
                multiply = bigInteger.multiply(bigInteger2);
                if (multiply.bitLength() == this.param.getStrength()) {
                    break;
                }
                bigInteger = bigInteger.max(bigInteger2);
            }
        }
        if (bigInteger.compareTo(bigInteger2) < 0) {
            bigInteger3 = bigInteger2;
            bigInteger2 = bigInteger;
        } else {
            bigInteger3 = bigInteger;
        }
        bigInteger = bigInteger3.subtract(ONE);
        BigInteger subtract = bigInteger2.subtract(ONE);
        BigInteger modInverse = publicExponent.modInverse(bigInteger.multiply(subtract));
        return new AsymmetricCipherKeyPair(new RSAKeyParameters(false, multiply, publicExponent), new RSAPrivateCrtKeyParameters(multiply, publicExponent, modInverse, bigInteger3, bigInteger2, modInverse.remainder(bigInteger), modInverse.remainder(subtract), bigInteger2.modInverse(bigInteger3)));
    }

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (RSAKeyGenerationParameters) keyGenerationParameters;
    }
}
