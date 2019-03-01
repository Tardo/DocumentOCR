package org.bouncycastle.tsp;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.tsp.Accuracy;

public class GenTimeAccuracy {
    private Accuracy accuracy;

    public GenTimeAccuracy(Accuracy accuracy) {
        this.accuracy = accuracy;
    }

    private String format(int i) {
        return i < 10 ? "00" + i : i < 100 ? "0" + i : Integer.toString(i);
    }

    private int getTimeComponent(DERInteger dERInteger) {
        return dERInteger != null ? dERInteger.getValue().intValue() : 0;
    }

    public int getMicros() {
        return getTimeComponent(this.accuracy.getMicros());
    }

    public int getMillis() {
        return getTimeComponent(this.accuracy.getMillis());
    }

    public int getSeconds() {
        return getTimeComponent(this.accuracy.getSeconds());
    }

    public String toString() {
        return getSeconds() + "." + format(getMillis()) + format(getMicros());
    }
}
