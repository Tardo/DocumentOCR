package org.bouncycastle.crypto.ec;

import org.bouncycastle.math.ec.ECPoint;

public class ECPair {
    /* renamed from: x */
    private final ECPoint f74x;
    /* renamed from: y */
    private final ECPoint f75y;

    public ECPair(ECPoint eCPoint, ECPoint eCPoint2) {
        this.f74x = eCPoint;
        this.f75y = eCPoint2;
    }

    public byte[] getEncoded() {
        Object encoded = this.f74x.getEncoded();
        Object encoded2 = this.f75y.getEncoded();
        Object obj = new byte[(encoded.length + encoded2.length)];
        System.arraycopy(encoded, 0, obj, 0, encoded.length);
        System.arraycopy(encoded2, 0, obj, encoded.length, encoded2.length);
        return obj;
    }

    public ECPoint getX() {
        return this.f74x;
    }

    public ECPoint getY() {
        return this.f75y;
    }
}
