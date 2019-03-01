package org.bouncycastle.cms;

public class CMSException extends Exception {
    /* renamed from: e */
    Exception f46e;

    public CMSException(String str) {
        super(str);
    }

    public CMSException(String str, Exception exception) {
        super(str);
        this.f46e = exception;
    }

    public Throwable getCause() {
        return this.f46e;
    }

    public Exception getUnderlyingException() {
        return this.f46e;
    }
}
