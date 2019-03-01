package org.bouncycastle.crypto.tls;

public abstract class AbstractTlsSigner implements TlsSigner {
    protected TlsContext context;

    public void init(TlsContext tlsContext) {
        this.context = tlsContext;
    }
}
