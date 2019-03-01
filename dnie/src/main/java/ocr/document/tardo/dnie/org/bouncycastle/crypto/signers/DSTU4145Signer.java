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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class DSTU4145Signer implements DSA {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private ECKeyParameters key;
    private SecureRandom random;

    private static BigInteger fieldElement2Integer(BigInteger bigInteger, ECFieldElement eCFieldElement) {
        BigInteger toBigInteger = eCFieldElement.toBigInteger();
        while (toBigInteger.bitLength() >= bigInteger.bitLength()) {
            toBigInteger = toBigInteger.clearBit(toBigInteger.bitLength() - 1);
        }
        return toBigInteger;
    }

    private static BigInteger generateRandomInteger(BigInteger bigInteger, SecureRandom secureRandom) {
        return new BigInteger(bigInteger.bitLength() - 1, secureRandom);
    }

    private static ECFieldElement hash2FieldElement(ECCurve eCCurve, byte[] bArr) {
        byte[] clone = Arrays.clone(bArr);
        reverseBytes(clone);
        BigInteger bigInteger = new BigInteger(1, clone);
        while (bigInteger.bitLength() >= eCCurve.getFieldSize()) {
            bigInteger = bigInteger.clearBit(bigInteger.bitLength() - 1);
        }
        return eCCurve.fromBigInteger(bigInteger);
    }

    private static void reverseBytes(byte[] bArr) {
        for (int i = 0; i < bArr.length / 2; i++) {
            byte b = bArr[i];
            bArr[i] = bArr[(bArr.length - 1) - i];
            bArr[(bArr.length - 1) - i] = b;
        }
    }

    public BigInteger[] generateSignature(byte[] bArr) {
        ECFieldElement hash2FieldElement = hash2FieldElement(this.key.getParameters().getCurve(), bArr);
        ECFieldElement fromBigInteger = hash2FieldElement.toBigInteger().signum() == 0 ? this.key.getParameters().getCurve().fromBigInteger(ONE) : hash2FieldElement;
        while (true) {
            BigInteger generateRandomInteger = generateRandomInteger(this.key.getParameters().getN(), this.random);
            hash2FieldElement = this.key.getParameters().getG().multiply(generateRandomInteger).getX();
            if (hash2FieldElement.toBigInteger().signum() != 0) {
                BigInteger fieldElement2Integer = fieldElement2Integer(this.key.getParameters().getN(), fromBigInteger.multiply(hash2FieldElement));
                if (fieldElement2Integer.signum() != 0) {
                    if (fieldElement2Integer.multiply(((ECPrivateKeyParameters) this.key).getD()).add(generateRandomInteger).mod(this.key.getParameters().getN()).signum() != 0) {
                        return new BigInteger[]{fieldElement2Integer, fieldElement2Integer.multiply(((ECPrivateKeyParameters) this.key).getD()).add(generateRandomInteger).mod(this.key.getParameters().getN())};
                    }
                } else {
                    continue;
                }
            }
        }
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        if (z) {
            CipherParameters parameters;
            if (cipherParameters instanceof ParametersWithRandom) {
                ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
                this.random = parametersWithRandom.getRandom();
                parameters = parametersWithRandom.getParameters();
            } else {
                this.random = new SecureRandom();
                parameters = cipherParameters;
            }
            this.key = (ECPrivateKeyParameters) parameters;
            return;
        }
        this.key = (ECPublicKeyParameters) cipherParameters;
    }

    public boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2) {
        if (bigInteger.signum() == 0 || bigInteger2.signum() == 0 || bigInteger.compareTo(this.key.getParameters().getN()) >= 0 || bigInteger2.compareTo(this.key.getParameters().getN()) >= 0) {
            return false;
        }
        ECFieldElement hash2FieldElement = hash2FieldElement(this.key.getParameters().getCurve(), bArr);
        ECFieldElement fromBigInteger = hash2FieldElement.toBigInteger().signum() == 0 ? this.key.getParameters().getCurve().fromBigInteger(ONE) : hash2FieldElement;
        ECPoint sumOfTwoMultiplies = ECAlgorithms.sumOfTwoMultiplies(this.key.getParameters().getG(), bigInteger2, ((ECPublicKeyParameters) this.key).getQ(), bigInteger);
        if (sumOfTwoMultiplies.isInfinity()) {
            return false;
        }
        return fieldElement2Integer(this.key.getParameters().getN(), fromBigInteger.multiply(sumOfTwoMultiplies.getX())).compareTo(bigInteger) == 0;
    }
}
