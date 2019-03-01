package com.jcraft.jzlib;

public final class Adler32 implements Checksum {
    private static final int BASE = 65521;
    private static final int NMAX = 5552;
    private long s1 = 1;
    private long s2 = 0;

    public void reset(long init) {
        this.s1 = init & 65535;
        this.s2 = (init >> 16) & 65535;
    }

    public void reset() {
        this.s1 = 1;
        this.s2 = 0;
    }

    public long getValue() {
        return (this.s2 << 16) | this.s1;
    }

    public void update(byte[] buf, int index, int len) {
        if (len == 1) {
            int index2 = index + 1;
            this.s1 += (long) (buf[index] & 255);
            this.s2 += this.s1;
            this.s1 %= 65521;
            this.s2 %= 65521;
            index = index2;
            return;
        }
        int k;
        int k2;
        int len2 = len % NMAX;
        int len1 = len / NMAX;
        while (true) {
            int len12 = len1 - 1;
            if (len1 <= 0) {
                break;
            }
            len -= NMAX;
            k = NMAX;
            index2 = index;
            while (true) {
                k2 = k - 1;
                if (k <= 0) {
                    break;
                }
                index = index2 + 1;
                this.s1 += (long) (buf[index2] & 255);
                this.s2 += this.s1;
                k = k2;
                index2 = index;
            }
            this.s1 %= 65521;
            this.s2 %= 65521;
            len1 = len12;
            index = index2;
        }
        k2 = len2;
        len -= k2;
        k = k2;
        index2 = index;
        while (true) {
            k2 = k - 1;
            if (k > 0) {
                index = index2 + 1;
                this.s1 += (long) (buf[index2] & 255);
                this.s2 += this.s1;
                k = k2;
                index2 = index;
            } else {
                this.s1 %= 65521;
                this.s2 %= 65521;
                index = index2;
                return;
            }
        }
    }

    public Adler32 copy() {
        Adler32 foo = new Adler32();
        foo.s1 = this.s1;
        foo.s2 = this.s2;
        return foo;
    }

    static long combine(long adler1, long adler2, long len2) {
        long rem = len2 % 65521;
        long sum1 = adler1 & 65535;
        sum1 += ((65535 & adler2) + 65521) - 1;
        long sum2 = ((rem * sum1) % 65521) + (((((adler1 >> 16) & 65535) + ((adler2 >> 16) & 65535)) + 65521) - rem);
        if (sum1 >= 65521) {
            sum1 -= 65521;
        }
        if (sum1 >= 65521) {
            sum1 -= 65521;
        }
        if (sum2 >= (65521 << 1)) {
            sum2 -= 65521 << 1;
        }
        if (sum2 >= 65521) {
            sum2 -= 65521;
        }
        return (sum2 << 16) | sum1;
    }
}
