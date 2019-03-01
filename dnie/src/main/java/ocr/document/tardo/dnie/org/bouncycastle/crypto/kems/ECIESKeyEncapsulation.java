package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class ECIESKeyEncapsulation implements KeyEncapsulation {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;
    private DerivationFunction kdf;
    private ECKeyParameters key;
    private SecureRandom rnd;

    public ECIESKeyEncapsulation(DerivationFunction derivationFunction, SecureRandom secureRandom) {
        this.kdf = derivationFunction;
        this.rnd = secureRandom;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    public ECIESKeyEncapsulation(DerivationFunction derivationFunction, SecureRandom secureRandom, boolean z, boolean z2, boolean z3) {
        this.kdf = derivationFunction;
        this.rnd = secureRandom;
        this.CofactorMode = z;
        this.OldCofactorMode = z2;
        this.SingleHashMode = z3;
    }

    public CipherParameters decrypt(byte[] bArr, int i) {
        return decrypt(bArr, 0, bArr.length, i);
    }

    public CipherParameters decrypt(byte[] bArr, int i, int i2, int i3) throws IllegalArgumentException {
        if (this.key instanceof ECPrivateKeyParameters) {
            byte[] bArr2;
            BigInteger n = this.key.getParameters().getN();
            BigInteger h = this.key.getParameters().getH();
            Object obj = new byte[i2];
            System.arraycopy(bArr, i, obj, 0, i2);
            ECPoint decodePoint = this.key.getParameters().getCurve().decodePoint(obj);
            ECPoint multiply = (this.CofactorMode || this.OldCofactorMode) ? decodePoint.multiply(h) : decodePoint;
            Object asUnsignedByteArray = BigIntegers.asUnsignedByteArray((this.key.getParameters().getCurve().getFieldSize() + 7) / 8, multiply.multiply(this.CofactorMode ? ((ECPrivateKeyParameters) this.key).getD().multiply(h.modInverse(n)).mod(n) : ((ECPrivateKeyParameters) this.key).getD()).getX().toBigInteger());
            if (this.SingleHashMode) {
                bArr2 = new byte[(obj.length + asUnsignedByteArray.length)];
                System.arraycopy(obj, 0, bArr2, 0, obj.length);
                System.arraycopy(asUnsignedByteArray, 0, bArr2, obj.length, asUnsignedByteArray.length);
            } else {
                Object obj2 = asUnsignedByteArray;
            }
            this.kdf.init(new KDFParameters(bArr2, null));
            bArr2 = new byte[i3];
            this.kdf.generateBytes(bArr2, 0, bArr2.length);
            return new KeyParameter(bArr2);
        }
        throw new IllegalArgumentException("Private key required for encryption");
    }

    public CipherParameters encrypt(byte[] bArr, int i) {
        return encrypt(bArr, 0, i);
    }

    public CipherParameters encrypt(byte[] bArr, int i, int i2) throws IllegalArgumentException {
        if (this.key instanceof ECPublicKeyParameters) {
            byte[] bArr2;
            BigInteger n = this.key.getParameters().getN();
            BigInteger h = this.key.getParameters().getH();
            BigInteger createRandomInRange = BigIntegers.createRandomInRange(ONE, n, this.rnd);
            Object encoded = this.key.getParameters().getG().multiply(createRandomInRange).getEncoded();
            System.arraycopy(encoded, 0, bArr, i, encoded.length);
            Object asUnsignedByteArray = BigIntegers.asUnsignedByteArray((this.key.getParameters().getCurve().getFieldSize() + 7) / 8, ((ECPublicKeyParameters) this.key).getQ().multiply(this.CofactorMode ? createRandomInRange.multiply(h).mod(n) : createRandomInRange).getX().toBigInteger());
            if (this.SingleHashMode) {
                bArr2 = new byte[(encoded.length + asUnsignedByteArray.length)];
                System.arraycopy(encoded, 0, bArr2, 0, encoded.length);
                System.arraycopy(asUnsignedByteArray, 0, bArr2, encoded.length, asUnsignedByteArray.length);
            } else {
                Object obj = asUnsignedByteArray;
            }
            this.kdf.init(new KDFParameters(bArr2, null));
            bArr2 = new byte[i2];
            this.kdf.generateBytes(bArr2, 0, bArr2.length);
            return new KeyParameter(bArr2);
        }
        throw new IllegalArgumentException("Public key required for encryption");
    }

    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof ECKeyParameters) {
            this.key = (ECKeyParameters) cipherParameters;
            return;
        }
        throw new IllegalArgumentException("EC key required");
    }
}
