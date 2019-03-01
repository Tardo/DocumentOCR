package org.bouncycastle.ocsp;

public class OCSPException extends Exception {
    /* renamed from: e */
    Exception f118e;

    public OCSPException(String str) {
        super(str);
    }

    public OCSPException(String str, Exception exception) {
        super(str);
        this.f118e = exception;
    }

    public Throwable getCause() {
        return this.f118e;
    }

    public Exception getUnderlyingException() {
        return this.f118e;
    }
}
