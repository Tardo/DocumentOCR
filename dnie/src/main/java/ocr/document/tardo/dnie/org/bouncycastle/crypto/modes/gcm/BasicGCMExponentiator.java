package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;

public class BasicGCMExponentiator implements GCMExponentiator {
    /* renamed from: x */
    private byte[] f266x;

    public void exponentiateX(long j, byte[] bArr) {
        Object oneAsBytes = GCMUtil.oneAsBytes();
        if (j > 0) {
            byte[] clone = Arrays.clone(this.f266x);
            do {
                if ((1 & j) != 0) {
                    GCMUtil.multiply(oneAsBytes, clone);
                }
                GCMUtil.multiply(clone, clone);
                j >>>= 1;
            } while (j > 0);
        }
        System.arraycopy(oneAsBytes, 0, bArr, 0, 16);
    }

    public void init(byte[] bArr) {
        this.f266x = Arrays.clone(bArr);
    }
}
