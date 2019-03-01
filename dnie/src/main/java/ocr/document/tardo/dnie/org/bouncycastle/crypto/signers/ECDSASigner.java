package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

public class ECDSASigner implements ECConstants, DSA {
    ECKeyParameters key;
    SecureRandom random;

    private BigInteger calculateE(BigInteger bigInteger, byte[] bArr) {
        int bitLength = bigInteger.bitLength();
        int length = bArr.length * 8;
        return bitLength >= length ? new BigInteger(1, bArr) : new BigInteger(1, bArr).shiftRight(length - bitLength);
    }

    public BigInteger[] generateSignature(byte[] bArr) {
        BigInteger bigInteger;
        BigInteger mod;
        BigInteger n = this.key.getParameters().getN();
        BigInteger calculateE = calculateE(n, bArr);
        do {
            int bitLength = n.bitLength();
            while (true) {
                bigInteger = new BigInteger(bitLength, this.random);
                if (!bigInteger.equals(ZERO) && bigInteger.compareTo(n) < 0) {
                    mod = this.key.getParameters().getG().multiply(bigInteger).getX().toBigInteger().mod(n);
                    if (!mod.equals(ZERO)) {
                    }
                }
            }
        } while (bigInteger.modInverse(n).multiply(calculateE.add(((ECPrivateKeyParameters) this.key).getD().multiply(mod))).mod(n).equals(ZERO));
        return new BigInteger[]{mod, bigInteger.modInverse(n).multiply(calculateE.add(((ECPrivateKeyParameters) this.key).getD().multiply(mod))).mod(n)};
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.key = (ECPublicKeyParameters) cipherParameters;
        } else if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            this.key = (ECPrivateKeyParameters) parametersWithRandom.getParameters();
        } else {
            this.random = new SecureRandom();
            this.key = (ECPrivateKeyParameters) cipherParameters;
        }
    }

    public boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2) {
        BigInteger n = this.key.getParameters().getN();
        BigInteger calculateE = calculateE(n, bArr);
        if (bigInteger.compareTo(ONE) < 0 || bigInteger.compareTo(n) >= 0) {
            return false;
        }
        if (bigInteger2.compareTo(ONE) < 0 || bigInteger2.compareTo(n) >= 0) {
            return false;
        }
        BigInteger modInverse = bigInteger2.modInverse(n);
        ECPoint sumOfTwoMultiplies = ECAlgorithms.sumOfTwoMultiplies(this.key.getParameters().getG(), calculateE.multiply(modInverse).mod(n), ((ECPublicKeyParameters) this.key).getQ(), bigInteger.multiply(modInverse).mod(n));
        return sumOfTwoMultiplies.isInfinity() ? false : sumOfTwoMultiplies.getX().toBigInteger().mod(n).equals(bigInteger);
    }
}
