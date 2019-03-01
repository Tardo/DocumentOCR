package org.spongycastle.i18n.filter;

public class TrustedInput {
    protected Object input;

    public TrustedInput(Object input) {
        this.input = input;
    }

    public Object getInput() {
        return this.input;
    }

    public String toString() {
        return this.input.toString();
    }
}
