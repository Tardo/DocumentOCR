package org.bouncycastle.crypto.tls;

public class TlsRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1928023487348344086L;
    /* renamed from: e */
    Throwable f82e;

    public TlsRuntimeException(String str) {
        super(str);
    }

    public TlsRuntimeException(String str, Throwable th) {
        super(str);
        this.f82e = th;
    }

    public Throwable getCause() {
        return this.f82e;
    }
}
