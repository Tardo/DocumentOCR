package org.spongycastle.ocsp;

public class OCSPException extends Exception {
    /* renamed from: e */
    Exception f203e;

    public OCSPException(String name) {
        super(name);
    }

    public OCSPException(String name, Exception e) {
        super(name);
        this.f203e = e;
    }

    public Exception getUnderlyingException() {
        return this.f203e;
    }

    public Throwable getCause() {
        return this.f203e;
    }
}
