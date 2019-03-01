package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;

public class SRP6VerifierGenerator {
    /* renamed from: N */
    protected BigInteger f72N;
    protected Digest digest;
    /* renamed from: g */
    protected BigInteger f73g;

    public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return this.f73g.modPow(SRP6Util.calculateX(this.digest, this.f72N, bArr, bArr2, bArr3), this.f72N);
    }

    public void init(BigInteger bigInteger, BigInteger bigInteger2, Digest digest) {
        this.f72N = bigInteger;
        this.f73g = bigInteger2;
        this.digest = digest;
    }
}
