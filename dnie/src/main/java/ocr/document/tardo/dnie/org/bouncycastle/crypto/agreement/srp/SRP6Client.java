package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

public class SRP6Client {
    /* renamed from: A */
    protected BigInteger f56A;
    /* renamed from: B */
    protected BigInteger f57B;
    /* renamed from: N */
    protected BigInteger f58N;
    /* renamed from: S */
    protected BigInteger f59S;
    /* renamed from: a */
    protected BigInteger f60a;
    protected Digest digest;
    /* renamed from: g */
    protected BigInteger f61g;
    protected SecureRandom random;
    /* renamed from: u */
    protected BigInteger f62u;
    /* renamed from: x */
    protected BigInteger f63x;

    private BigInteger calculateS() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f58N, this.f61g);
        return this.f57B.subtract(this.f61g.modPow(this.f63x, this.f58N).multiply(calculateK).mod(this.f58N)).mod(this.f58N).modPow(this.f62u.multiply(this.f63x).add(this.f60a), this.f58N);
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        this.f57B = SRP6Util.validatePublicValue(this.f58N, bigInteger);
        this.f62u = SRP6Util.calculateU(this.digest, this.f58N, this.f56A, this.f57B);
        this.f59S = calculateS();
        return this.f59S;
    }

    public BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this.f63x = SRP6Util.calculateX(this.digest, this.f58N, bArr, bArr2, bArr3);
        this.f60a = selectPrivateValue();
        this.f56A = this.f61g.modPow(this.f60a, this.f58N);
        return this.f56A;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest, SecureRandom secureRandom) {
        this.f58N = bigInteger;
        this.f61g = bigInteger2;
        this.digest = digest;
        this.random = secureRandom;
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f58N, this.f61g, this.random);
    }
}
