package org.bouncycastle.cms;

public class CMSAttributeTableGenerationException extends CMSRuntimeException {
    /* renamed from: e */
    Exception f228e;

    public CMSAttributeTableGenerationException(String str) {
        super(str);
    }

    public CMSAttributeTableGenerationException(String str, Exception exception) {
        super(str);
        this.f228e = exception;
    }

    public Throwable getCause() {
        return this.f228e;
    }

    public Exception getUnderlyingException() {
        return this.f228e;
    }
}
