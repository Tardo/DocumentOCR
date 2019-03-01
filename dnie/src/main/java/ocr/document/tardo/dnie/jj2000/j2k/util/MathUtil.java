package jj2000.j2k.util;

public class MathUtil {
    public static int log2(int x) {
        if (x <= 0) {
            throw new IllegalArgumentException("" + x + " <= 0");
        }
        int v = x;
        int y = -1;
        while (v > 0) {
            v >>= 1;
            y++;
        }
        return y;
    }

    public static final int lcm(int x1, int x2) {
        if (x1 <= 0 || x2 <= 0) {
            throw new IllegalArgumentException("Cannot compute the least common multiple of two numbers if one, at least,is negative.");
        }
        int max;
        int min;
        if (x1 > x2) {
            max = x1;
            min = x2;
        } else {
            max = x2;
            min = x1;
        }
        for (int i = 1; i <= min; i++) {
            if ((max * i) % min == 0) {
                return i * max;
            }
        }
        throw new Error("Cannot find the least common multiple of numbers " + x1 + " and " + x2);
    }

    public static final int lcm(int[] x) {
        if (x.length < 2) {
            throw new Error("Do not use this method if there are less than two numbers.");
        }
        int tmp = lcm(x[x.length - 1], x[x.length - 2]);
        for (int i = x.length - 3; i >= 0; i--) {
            if (x[i] <= 0) {
                throw new IllegalArgumentException("Cannot compute the least common multiple of several numbers where one, at least,is negative.");
            }
            tmp = lcm(tmp, x[i]);
        }
        return tmp;
    }

    public static final int gcd(int x1, int x2) {
        if (x1 < 0 || x2 < 0) {
            throw new IllegalArgumentException("Cannot compute the GCD if one integer is negative.");
        }
        int a;
        int b;
        if (x1 > x2) {
            a = x1;
            b = x2;
        } else {
            a = x2;
            b = x1;
        }
        if (b == 0) {
            return 0;
        }
        int g = b;
        while (g != 0) {
            int z = a % g;
            a = g;
            g = z;
        }
        return a;
    }

    public static final int gcd(int[] x) {
        if (x.length < 2) {
            throw new Error("Do not use this method if there are less than two numbers.");
        }
        int tmp = gcd(x[x.length - 1], x[x.length - 2]);
        for (int i = x.length - 3; i >= 0; i--) {
            if (x[i] < 0) {
                throw new IllegalArgumentException("Cannot compute the least common multiple of several numbers where one, at least,is negative.");
            }
            tmp = gcd(tmp, x[i]);
        }
        return tmp;
    }
}
