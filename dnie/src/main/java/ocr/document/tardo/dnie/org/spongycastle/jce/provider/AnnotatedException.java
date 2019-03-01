package org.spongycastle.jce.provider;

import org.spongycastle.jce.exception.ExtException;

public class AnnotatedException extends Exception implements ExtException {
    private Throwable _underlyingException;

    AnnotatedException(String string, Throwable e) {
        super(string);
        this._underlyingException = e;
    }

    AnnotatedException(String string) {
        this(string, null);
    }

    Throwable getUnderlyingException() {
        return this._underlyingException;
    }

    public Throwable getCause() {
        return this._underlyingException;
    }
}
