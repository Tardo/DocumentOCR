package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;

class CombinedHash implements TlsHandshakeHash {
    protected TlsContext context;
    protected Digest md5;
    protected Digest sha1;

    CombinedHash() {
        this.md5 = TlsUtils.createHash(1);
        this.sha1 = TlsUtils.createHash(2);
    }

    CombinedHash(CombinedHash combinedHash) {
        this.context = combinedHash.context;
        this.md5 = TlsUtils.cloneHash(1, combinedHash.md5);
        this.sha1 = TlsUtils.cloneHash(2, combinedHash.sha1);
    }

    public TlsHandshakeHash commit() {
        return this;
    }

    public int doFinal(byte[] bArr, int i) {
        if (this.context != null && this.context.getServerVersion().isSSL()) {
            ssl3Complete(this.md5, SSL3Mac.IPAD, SSL3Mac.OPAD, 48);
            ssl3Complete(this.sha1, SSL3Mac.IPAD, SSL3Mac.OPAD, 40);
        }
        int doFinal = this.md5.doFinal(bArr, i);
        return doFinal + this.sha1.doFinal(bArr, i + doFinal);
    }

    public TlsHandshakeHash fork() {
        return new CombinedHash(this);
    }

    public String getAlgorithmName() {
        return this.md5.getAlgorithmName() + " and " + this.sha1.getAlgorithmName();
    }

    public int getDigestSize() {
        return this.md5.getDigestSize() + this.sha1.getDigestSize();
    }

    public void init(TlsContext tlsContext) {
        this.context = tlsContext;
    }

    public void reset() {
        this.md5.reset();
        this.sha1.reset();
    }

    protected void ssl3Complete(Digest digest, byte[] bArr, byte[] bArr2, int i) {
        byte[] bArr3 = this.context.getSecurityParameters().masterSecret;
        digest.update(bArr3, 0, bArr3.length);
        digest.update(bArr, 0, i);
        byte[] bArr4 = new byte[digest.getDigestSize()];
        digest.doFinal(bArr4, 0);
        digest.update(bArr3, 0, bArr3.length);
        digest.update(bArr2, 0, i);
        digest.update(bArr4, 0, bArr4.length);
    }

    public void update(byte b) {
        this.md5.update(b);
        this.sha1.update(b);
    }

    public void update(byte[] bArr, int i, int i2) {
        this.md5.update(bArr, i, i2);
        this.sha1.update(bArr, i, i2);
    }
}
