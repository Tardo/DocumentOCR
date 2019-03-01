package org.bouncycastle.cms;

public class CMSRuntimeException extends RuntimeException {
    /* renamed from: e */
    Exception f47e;

    public CMSRuntimeException(String str) {
        super(str);
    }

    public CMSRuntimeException(String str, Exception exception) {
        super(str);
        this.f47e = exception;
    }

    public Throwable getCause() {
        return this.f47e;
    }

    public Exception getUnderlyingException() {
        return this.f47e;
    }
}
