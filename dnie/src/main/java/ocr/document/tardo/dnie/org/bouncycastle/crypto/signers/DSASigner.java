package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class DSASigner implements DSA {
    DSAKeyParameters key;
    SecureRandom random;

    private BigInteger calculateE(BigInteger bigInteger, byte[] bArr) {
        if (bigInteger.bitLength() >= bArr.length * 8) {
            return new BigInteger(1, bArr);
        }
        Object obj = new byte[(bigInteger.bitLength() / 8)];
        System.arraycopy(bArr, 0, obj, 0, obj.length);
        return new BigInteger(1, obj);
    }

    public BigInteger[] generateSignature(byte[] bArr) {
        BigInteger bigInteger;
        DSAParameters parameters = this.key.getParameters();
        BigInteger calculateE = calculateE(parameters.getQ(), bArr);
        int bitLength = parameters.getQ().bitLength();
        do {
            bigInteger = new BigInteger(bitLength, this.random);
        } while (bigInteger.compareTo(parameters.getQ()) >= 0);
        BigInteger mod = bigInteger.modInverse(parameters.getQ()).multiply(calculateE.add(((DSAPrivateKeyParameters) this.key).getX().multiply(parameters.getG().modPow(bigInteger, parameters.getP()).mod(parameters.getQ())))).mod(parameters.getQ());
        return new BigInteger[]{r4, mod};
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.key = (DSAPublicKeyParameters) cipherParameters;
        } else if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            this.key = (DSAPrivateKeyParameters) parametersWithRandom.getParameters();
        } else {
            this.random = new SecureRandom();
            this.key = (DSAPrivateKeyParameters) cipherParameters;
        }
    }

    public boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2) {
        DSAParameters parameters = this.key.getParameters();
        BigInteger calculateE = calculateE(parameters.getQ(), bArr);
        BigInteger valueOf = BigInteger.valueOf(0);
        if (valueOf.compareTo(bigInteger) >= 0 || parameters.getQ().compareTo(bigInteger) <= 0 || valueOf.compareTo(bigInteger2) >= 0 || parameters.getQ().compareTo(bigInteger2) <= 0) {
            return false;
        }
        BigInteger modInverse = bigInteger2.modInverse(parameters.getQ());
        return parameters.getG().modPow(calculateE.multiply(modInverse).mod(parameters.getQ()), parameters.getP()).multiply(((DSAPublicKeyParameters) this.key).getY().modPow(bigInteger.multiply(modInverse).mod(parameters.getQ()), parameters.getP())).mod(parameters.getP()).mod(parameters.getQ()).equals(bigInteger);
    }
}
