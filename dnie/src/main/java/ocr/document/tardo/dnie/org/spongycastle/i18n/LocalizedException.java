package org.spongycastle.i18n;

import java.util.Locale;

public class LocalizedException extends Exception {
    private Throwable cause;
    protected ErrorBundle message;

    public LocalizedException(ErrorBundle message) {
        super(message.getText(Locale.getDefault()));
        this.message = message;
    }

    public LocalizedException(ErrorBundle message, Throwable throwable) {
        super(message.getText(Locale.getDefault()));
        this.message = message;
        this.cause = throwable;
    }

    public ErrorBundle getErrorMessage() {
        return this.message;
    }

    public Throwable getCause() {
        return this.cause;
    }
}
