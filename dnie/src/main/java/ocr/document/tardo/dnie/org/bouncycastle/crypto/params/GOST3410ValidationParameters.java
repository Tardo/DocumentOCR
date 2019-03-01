package org.bouncycastle.crypto.params;

public class GOST3410ValidationParameters {
    /* renamed from: c */
    private int f81c;
    private long cL;
    private int x0;
    private long x0L;

    public GOST3410ValidationParameters(int i, int i2) {
        this.x0 = i;
        this.f81c = i2;
    }

    public GOST3410ValidationParameters(long j, long j2) {
        this.x0L = j;
        this.cL = j2;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof GOST3410ValidationParameters)) {
            return false;
        }
        GOST3410ValidationParameters gOST3410ValidationParameters = (GOST3410ValidationParameters) obj;
        return gOST3410ValidationParameters.f81c == this.f81c && gOST3410ValidationParameters.x0 == this.x0 && gOST3410ValidationParameters.cL == this.cL && gOST3410ValidationParameters.x0L == this.x0L;
    }

    public int getC() {
        return this.f81c;
    }

    public long getCL() {
        return this.cL;
    }

    public int getX0() {
        return this.x0;
    }

    public long getX0L() {
        return this.x0L;
    }

    public int hashCode() {
        return ((((this.x0 ^ this.f81c) ^ ((int) this.x0L)) ^ ((int) (this.x0L >> 32))) ^ ((int) this.cL)) ^ ((int) (this.cL >> 32));
    }
}
