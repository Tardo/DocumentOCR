package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

public class SRP6Server {
    /* renamed from: A */
    protected BigInteger f64A;
    /* renamed from: B */
    protected BigInteger f65B;
    /* renamed from: N */
    protected BigInteger f66N;
    /* renamed from: S */
    protected BigInteger f67S;
    /* renamed from: b */
    protected BigInteger f68b;
    protected Digest digest;
    /* renamed from: g */
    protected BigInteger f69g;
    protected SecureRandom random;
    /* renamed from: u */
    protected BigInteger f70u;
    /* renamed from: v */
    protected BigInteger f71v;

    private BigInteger calculateS() {
        return this.f71v.modPow(this.f70u, this.f66N).multiply(this.f64A).mod(this.f66N).modPow(this.f68b, this.f66N);
    }

    public BigInteger calculateSecret(BigInteger bigInteger) throws CryptoException {
        this.f64A = SRP6Util.validatePublicValue(this.f66N, bigInteger);
        this.f70u = SRP6Util.calculateU(this.digest, this.f66N, this.f64A, this.f65B);
        this.f67S = calculateS();
        return this.f67S;
    }

    public BigInteger generateServerCredentials() {
        BigInteger calculateK = SRP6Util.calculateK(this.digest, this.f66N, this.f69g);
        this.f68b = selectPrivateValue();
        this.f65B = calculateK.multiply(this.f71v).mod(this.f66N).add(this.f69g.modPow(this.f68b, this.f66N)).mod(this.f66N);
        return this.f65B;
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, Digest digest, SecureRandom secureRandom) {
        this.f66N = bigInteger;
        this.f69g = bigInteger2;
        this.f71v = bigInteger3;
        this.random = secureRandom;
        this.digest = digest;
    }

    protected BigInteger selectPrivateValue() {
        return SRP6Util.generatePrivateValue(this.digest, this.f66N, this.f69g, this.random);
    }
}
