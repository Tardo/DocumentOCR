package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.exception.ExtException;

public class AnnotatedException extends Exception implements ExtException {
    private Throwable _underlyingException;

    AnnotatedException(String str) {
        this(str, null);
    }

    AnnotatedException(String str, Throwable th) {
        super(str);
        this._underlyingException = th;
    }

    public Throwable getCause() {
        return this._underlyingException;
    }

    Throwable getUnderlyingException() {
        return this._underlyingException;
    }
}
