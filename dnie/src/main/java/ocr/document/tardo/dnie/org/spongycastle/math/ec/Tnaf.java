package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.spongycastle.math.ec.ECPoint.F2m;

class Tnaf {
    private static final BigInteger MINUS_ONE = ECConstants.ONE.negate();
    private static final BigInteger MINUS_THREE = ECConstants.THREE.negate();
    private static final BigInteger MINUS_TWO = ECConstants.TWO.negate();
    public static final byte POW_2_WIDTH = (byte) 16;
    public static final byte WIDTH = (byte) 4;
    public static final ZTauElement[] alpha0 = new ZTauElement[]{null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(MINUS_THREE, MINUS_ONE), null, new ZTauElement(MINUS_ONE, MINUS_ONE), null, new ZTauElement(ECConstants.ONE, MINUS_ONE), null};
    public static final byte[][] alpha0Tnaf;
    public static final ZTauElement[] alpha1 = new ZTauElement[]{null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(MINUS_THREE, ECConstants.ONE), null, new ZTauElement(MINUS_ONE, ECConstants.ONE), null, new ZTauElement(ECConstants.ONE, ECConstants.ONE), null};
    public static final byte[][] alpha1Tnaf;

    Tnaf() {
    }

    static {
        r0 = new byte[8][];
        r0[1] = new byte[]{(byte) 1};
        r0[2] = null;
        r0[3] = new byte[]{(byte) -1, (byte) 0, (byte) 1};
        r0[4] = null;
        r0[5] = new byte[]{(byte) 1, (byte) 0, (byte) 1};
        r0[6] = null;
        r0[7] = new byte[]{(byte) -1, (byte) 0, (byte) 0, (byte) 1};
        alpha0Tnaf = r0;
        r0 = new byte[8][];
        r0[1] = new byte[]{(byte) 1};
        r0[2] = null;
        r0[3] = new byte[]{(byte) -1, (byte) 0, (byte) 1};
        r0[4] = null;
        r0[5] = new byte[]{(byte) 1, (byte) 0, (byte) 1};
        r0[6] = null;
        r0[7] = new byte[]{(byte) -1, (byte) 0, (byte) 0, (byte) -1};
        alpha1Tnaf = r0;
    }

    public static BigInteger norm(byte mu, ZTauElement lambda) {
        BigInteger s1 = lambda.f201u.multiply(lambda.f201u);
        BigInteger s2 = lambda.f201u.multiply(lambda.f202v);
        BigInteger s3 = lambda.f202v.multiply(lambda.f202v).shiftLeft(1);
        if (mu == (byte) 1) {
            return s1.add(s2).add(s3);
        }
        if (mu == (byte) -1) {
            return s1.subtract(s2).add(s3);
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static SimpleBigDecimal norm(byte mu, SimpleBigDecimal u, SimpleBigDecimal v) {
        SimpleBigDecimal s1 = u.multiply(u);
        SimpleBigDecimal s2 = u.multiply(v);
        SimpleBigDecimal s3 = v.multiply(v).shiftLeft(1);
        if (mu == (byte) 1) {
            return s1.add(s2).add(s3);
        }
        if (mu == (byte) -1) {
            return s1.subtract(s2).add(s3);
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static ZTauElement round(SimpleBigDecimal lambda0, SimpleBigDecimal lambda1, byte mu) {
        if (lambda1.getScale() != lambda0.getScale()) {
            throw new IllegalArgumentException("lambda0 and lambda1 do not have same scale");
        } else if (mu == (byte) 1 || mu == (byte) -1) {
            SimpleBigDecimal check1;
            SimpleBigDecimal check2;
            BigInteger f0 = lambda0.round();
            BigInteger f1 = lambda1.round();
            SimpleBigDecimal eta0 = lambda0.subtract(f0);
            SimpleBigDecimal eta1 = lambda1.subtract(f1);
            SimpleBigDecimal eta = eta0.add(eta0);
            if (mu == (byte) 1) {
                eta = eta.add(eta1);
            } else {
                eta = eta.subtract(eta1);
            }
            SimpleBigDecimal threeEta1 = eta1.add(eta1).add(eta1);
            SimpleBigDecimal fourEta1 = threeEta1.add(eta1);
            if (mu == (byte) 1) {
                check1 = eta0.subtract(threeEta1);
                check2 = eta0.add(fourEta1);
            } else {
                check1 = eta0.add(threeEta1);
                check2 = eta0.subtract(fourEta1);
            }
            byte h0 = (byte) 0;
            byte h1 = (byte) 0;
            if (eta.compareTo(ECConstants.ONE) >= 0) {
                if (check1.compareTo(MINUS_ONE) < 0) {
                    h1 = mu;
                } else {
                    h0 = (byte) 1;
                }
            } else if (check2.compareTo(ECConstants.TWO) >= 0) {
                h1 = mu;
            }
            if (eta.compareTo(MINUS_ONE) < 0) {
                if (check1.compareTo(ECConstants.ONE) >= 0) {
                    h1 = (byte) (-mu);
                } else {
                    h0 = (byte) -1;
                }
            } else if (check2.compareTo(MINUS_TWO) < 0) {
                h1 = (byte) (-mu);
            }
            return new ZTauElement(f0.add(BigInteger.valueOf((long) h0)), f1.add(BigInteger.valueOf((long) h1)));
        } else {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
    }

    public static SimpleBigDecimal approximateDivisionByN(BigInteger k, BigInteger s, BigInteger vm, byte a, int m, int c) {
        int _k = ((m + 5) / 2) + c;
        BigInteger gs = s.multiply(k.shiftRight(((m - _k) - 2) + a));
        BigInteger gsPlusJs = gs.add(vm.multiply(gs.shiftRight(m)));
        BigInteger ls = gsPlusJs.shiftRight(_k - c);
        if (gsPlusJs.testBit((_k - c) - 1)) {
            ls = ls.add(ECConstants.ONE);
        }
        return new SimpleBigDecimal(ls, c);
    }

    public static byte[] tauAdicNaf(byte mu, ZTauElement lambda) {
        if (mu == (byte) 1 || mu == (byte) -1) {
            int log2Norm = norm(mu, lambda).bitLength();
            byte[] u = new byte[(log2Norm > 30 ? log2Norm + 4 : 34)];
            int i = 0;
            int length = 0;
            BigInteger r0 = lambda.f201u;
            BigInteger r1 = lambda.f202v;
            while (true) {
                if (r0.equals(ECConstants.ZERO) && r1.equals(ECConstants.ZERO)) {
                    length++;
                    byte[] tnaf = new byte[length];
                    System.arraycopy(u, 0, tnaf, 0, length);
                    return tnaf;
                }
                if (r0.testBit(0)) {
                    u[i] = (byte) ECConstants.TWO.subtract(r0.subtract(r1.shiftLeft(1)).mod(ECConstants.FOUR)).intValue();
                    if (u[i] == (byte) 1) {
                        r0 = r0.clearBit(0);
                    } else {
                        r0 = r0.add(ECConstants.ONE);
                    }
                    length = i;
                } else {
                    u[i] = (byte) 0;
                }
                BigInteger t = r0;
                BigInteger s = r0.shiftRight(1);
                if (mu == (byte) 1) {
                    r0 = r1.add(s);
                } else {
                    r0 = r1.subtract(s);
                }
                r1 = t.shiftRight(1).negate();
                i++;
            }
        } else {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
    }

    public static F2m tau(F2m p) {
        if (p.isInfinity()) {
            return p;
        }
        return new F2m(p.getCurve(), p.getX().square(), p.getY().square(), p.isCompressed());
    }

    public static byte getMu(ECCurve.F2m curve) {
        BigInteger a = curve.getA().toBigInteger();
        if (a.equals(ECConstants.ZERO)) {
            return (byte) -1;
        }
        if (a.equals(ECConstants.ONE)) {
            return (byte) 1;
        }
        throw new IllegalArgumentException("No Koblitz curve (ABC), TNAF multiplication not possible");
    }

    public static BigInteger[] getLucas(byte mu, int k, boolean doV) {
        if (mu == (byte) 1 || mu == (byte) -1) {
            BigInteger u0;
            BigInteger u1;
            if (doV) {
                u0 = ECConstants.TWO;
                u1 = BigInteger.valueOf((long) mu);
            } else {
                u0 = ECConstants.ZERO;
                u1 = ECConstants.ONE;
            }
            for (int i = 1; i < k; i++) {
                BigInteger s;
                if (mu == (byte) 1) {
                    s = u1;
                } else {
                    s = u1.negate();
                }
                u0 = u1;
                u1 = s.subtract(u0.shiftLeft(1));
            }
            return new BigInteger[]{u0, u1};
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static BigInteger getTw(byte mu, int w) {
        if (w != 4) {
            BigInteger[] us = getLucas(mu, w, false);
            BigInteger twoToW = ECConstants.ZERO.setBit(w);
            return ECConstants.TWO.multiply(us[0]).multiply(us[1].modInverse(twoToW)).mod(twoToW);
        } else if (mu == (byte) 1) {
            return BigInteger.valueOf(6);
        } else {
            return BigInteger.valueOf(10);
        }
    }

    public static BigInteger[] getSi(ECCurve.F2m curve) {
        if (curve.isKoblitz()) {
            BigInteger dividend0;
            BigInteger dividend1;
            int m = curve.getM();
            int a = curve.getA().toBigInteger().intValue();
            byte mu = curve.getMu();
            int h = curve.getH().intValue();
            BigInteger[] ui = getLucas(mu, (m + 3) - a, false);
            if (mu == (byte) 1) {
                dividend0 = ECConstants.ONE.subtract(ui[1]);
                dividend1 = ECConstants.ONE.subtract(ui[0]);
            } else if (mu == (byte) -1) {
                dividend0 = ECConstants.ONE.add(ui[1]);
                dividend1 = ECConstants.ONE.add(ui[0]);
            } else {
                throw new IllegalArgumentException("mu must be 1 or -1");
            }
            BigInteger[] si = new BigInteger[2];
            if (h == 2) {
                si[0] = dividend0.shiftRight(1);
                si[1] = dividend1.shiftRight(1).negate();
            } else if (h == 4) {
                si[0] = dividend0.shiftRight(2);
                si[1] = dividend1.shiftRight(2).negate();
            } else {
                throw new IllegalArgumentException("h (Cofactor) must be 2 or 4");
            }
            return si;
        }
        throw new IllegalArgumentException("si is defined for Koblitz curves only");
    }

    public static ZTauElement partModReduction(BigInteger k, int m, byte a, BigInteger[] s, byte mu, byte c) {
        BigInteger d0;
        if (mu == (byte) 1) {
            d0 = s[0].add(s[1]);
        } else {
            d0 = s[0].subtract(s[1]);
        }
        BigInteger vm = getLucas(mu, m, true)[1];
        ZTauElement q = round(approximateDivisionByN(k, s[0], vm, a, m, c), approximateDivisionByN(k, s[1], vm, a, m, c), mu);
        return new ZTauElement(k.subtract(d0.multiply(q.f201u)).subtract(BigInteger.valueOf(2).multiply(s[1]).multiply(q.f202v)), s[1].multiply(q.f201u).subtract(s[0].multiply(q.f202v)));
    }

    public static F2m multiplyRTnaf(F2m p, BigInteger k) {
        ECCurve.F2m curve = (ECCurve.F2m) p.getCurve();
        return multiplyTnaf(p, partModReduction(k, curve.getM(), (byte) curve.getA().toBigInteger().intValue(), curve.getSi(), curve.getMu(), (byte) 10));
    }

    public static F2m multiplyTnaf(F2m p, ZTauElement lambda) {
        return multiplyFromTnaf(p, tauAdicNaf(((ECCurve.F2m) p.getCurve()).getMu(), lambda));
    }

    public static F2m multiplyFromTnaf(F2m p, byte[] u) {
        F2m q = (F2m) ((ECCurve.F2m) p.getCurve()).getInfinity();
        for (int i = u.length - 1; i >= 0; i--) {
            q = tau(q);
            if (u[i] == (byte) 1) {
                q = q.addSimple(p);
            } else if (u[i] == (byte) -1) {
                q = q.subtractSimple(p);
            }
        }
        return q;
    }

    public static byte[] tauAdicWNaf(byte mu, ZTauElement lambda, byte width, BigInteger pow2w, BigInteger tw, ZTauElement[] alpha) {
        if (mu == (byte) 1 || mu == (byte) -1) {
            int log2Norm = norm(mu, lambda).bitLength();
            byte[] u = new byte[(log2Norm > 30 ? (log2Norm + 4) + width : width + 34)];
            BigInteger pow2wMin1 = pow2w.shiftRight(1);
            BigInteger r0 = lambda.f201u;
            BigInteger r1 = lambda.f202v;
            int i = 0;
            while (true) {
                if (r0.equals(ECConstants.ZERO) && r1.equals(ECConstants.ZERO)) {
                    return u;
                }
                if (r0.testBit(0)) {
                    byte uLocal;
                    BigInteger uUnMod = r0.add(r1.multiply(tw)).mod(pow2w);
                    if (uUnMod.compareTo(pow2wMin1) >= 0) {
                        uLocal = (byte) uUnMod.subtract(pow2w).intValue();
                    } else {
                        uLocal = (byte) uUnMod.intValue();
                    }
                    u[i] = uLocal;
                    boolean s = true;
                    if (uLocal < (byte) 0) {
                        s = false;
                        uLocal = (byte) (-uLocal);
                    }
                    if (s) {
                        r0 = r0.subtract(alpha[uLocal].f201u);
                        r1 = r1.subtract(alpha[uLocal].f202v);
                    } else {
                        r0 = r0.add(alpha[uLocal].f201u);
                        r1 = r1.add(alpha[uLocal].f202v);
                    }
                } else {
                    u[i] = (byte) 0;
                }
                BigInteger t = r0;
                if (mu == (byte) 1) {
                    r0 = r1.add(r0.shiftRight(1));
                } else {
                    r0 = r1.subtract(r0.shiftRight(1));
                }
                r1 = t.shiftRight(1).negate();
                i++;
            }
        } else {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
    }

    public static F2m[] getPreComp(F2m p, byte a) {
        byte[][] alphaTnaf;
        F2m[] pu = new F2m[16];
        pu[1] = p;
        if (a == (byte) 0) {
            alphaTnaf = alpha0Tnaf;
        } else {
            alphaTnaf = alpha1Tnaf;
        }
        int precompLen = alphaTnaf.length;
        for (int i = 3; i < precompLen; i += 2) {
            pu[i] = multiplyFromTnaf(p, alphaTnaf[i]);
        }
        return pu;
    }
}
