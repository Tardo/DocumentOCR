package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;

public class BasicGCMMultiplier implements GCMMultiplier {
    /* renamed from: H */
    private byte[] f267H;

    public void init(byte[] bArr) {
        this.f267H = Arrays.clone(bArr);
    }

    public void multiplyH(byte[] bArr) {
        GCMUtil.multiply(bArr, this.f267H);
    }
}
