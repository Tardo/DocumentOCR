package org.bouncycastle.crypto.modes.gcm;

import java.lang.reflect.Array;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

public class Tables64kGCMMultiplier implements GCMMultiplier {
    /* renamed from: H */
    private byte[] f268H;
    /* renamed from: M */
    private int[][][] f269M;

    public void init(byte[] bArr) {
        int i;
        if (this.f269M == null) {
            this.f269M = (int[][][]) Array.newInstance(Integer.TYPE, new int[]{16, 256, 4});
        } else if (Arrays.areEqual(this.f268H, bArr)) {
            return;
        }
        this.f268H = Arrays.clone(bArr);
        GCMUtil.asInts(bArr, this.f269M[0][128]);
        for (i = 64; i >= 1; i >>= 1) {
            GCMUtil.multiplyP(this.f269M[0][i + i], this.f269M[0][i]);
        }
        i = 0;
        while (true) {
            int i2;
            for (int i3 = 2; i3 < 256; i3 += i3) {
                for (i2 = 1; i2 < i3; i2++) {
                    GCMUtil.xor(this.f269M[i][i3], this.f269M[i][i2], this.f269M[i][i3 + i2]);
                }
            }
            i++;
            if (i != 16) {
                for (i2 = 128; i2 > 0; i2 >>= 1) {
                    GCMUtil.multiplyP8(this.f269M[i - 1][i2], this.f269M[i][i2]);
                }
            } else {
                return;
            }
        }
    }

    public void multiplyH(byte[] bArr) {
        int[] iArr = new int[4];
        for (int i = 15; i >= 0; i--) {
            int[] iArr2 = this.f269M[i][bArr[i] & 255];
            iArr[0] = iArr[0] ^ iArr2[0];
            iArr[1] = iArr[1] ^ iArr2[1];
            iArr[2] = iArr[2] ^ iArr2[2];
            iArr[3] = iArr2[3] ^ iArr[3];
        }
        Pack.intToBigEndian(iArr, bArr, 0);
    }
}
