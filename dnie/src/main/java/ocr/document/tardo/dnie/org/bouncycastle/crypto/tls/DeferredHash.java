package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.Digest;

class DeferredHash implements TlsHandshakeHash {
    private ByteArrayOutputStream buf;
    protected TlsContext context;
    private Digest hash;
    private int prfAlgorithm;

    DeferredHash() {
        this.buf = new ByteArrayOutputStream();
        this.prfAlgorithm = -1;
        this.hash = null;
        this.buf = new ByteArrayOutputStream();
        this.hash = null;
    }

    private DeferredHash(Digest digest) {
        this.buf = new ByteArrayOutputStream();
        this.prfAlgorithm = -1;
        this.hash = null;
        this.buf = null;
        this.hash = digest;
    }

    protected void checkHash() {
        if (this.hash == null) {
            throw new IllegalStateException("No hash algorithm has been set");
        }
    }

    public TlsHandshakeHash commit() {
        int prfAlgorithm = this.context.getSecurityParameters().getPrfAlgorithm();
        Digest createPRFHash = TlsUtils.createPRFHash(prfAlgorithm);
        byte[] toByteArray = this.buf.toByteArray();
        createPRFHash.update(toByteArray, 0, toByteArray.length);
        if (createPRFHash instanceof TlsHandshakeHash) {
            TlsHandshakeHash tlsHandshakeHash = (TlsHandshakeHash) createPRFHash;
            tlsHandshakeHash.init(this.context);
            return tlsHandshakeHash.commit();
        }
        this.prfAlgorithm = prfAlgorithm;
        this.hash = createPRFHash;
        this.buf = null;
        return this;
    }

    public int doFinal(byte[] bArr, int i) {
        checkHash();
        return this.hash.doFinal(bArr, i);
    }

    public TlsHandshakeHash fork() {
        checkHash();
        return new DeferredHash(TlsUtils.clonePRFHash(this.prfAlgorithm, this.hash));
    }

    public String getAlgorithmName() {
        checkHash();
        return this.hash.getAlgorithmName();
    }

    public int getDigestSize() {
        checkHash();
        return this.hash.getDigestSize();
    }

    public void init(TlsContext tlsContext) {
        this.context = tlsContext;
    }

    public void reset() {
        if (this.hash == null) {
            this.buf.reset();
        } else {
            this.hash.reset();
        }
    }

    public void update(byte b) {
        if (this.hash == null) {
            this.buf.write(b);
        } else {
            this.hash.update(b);
        }
    }

    public void update(byte[] bArr, int i, int i2) {
        if (this.hash == null) {
            this.buf.write(bArr, i, i2);
        } else {
            this.hash.update(bArr, i, i2);
        }
    }
}
