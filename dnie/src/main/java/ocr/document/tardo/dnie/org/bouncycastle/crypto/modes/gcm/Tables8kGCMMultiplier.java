package org.bouncycastle.crypto.modes.gcm;

import java.lang.reflect.Array;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

public class Tables8kGCMMultiplier implements GCMMultiplier {
    /* renamed from: H */
    private byte[] f270H;
    /* renamed from: M */
    private int[][][] f271M;

    public void init(byte[] bArr) {
        int i;
        if (this.f271M == null) {
            this.f271M = (int[][][]) Array.newInstance(Integer.TYPE, new int[]{32, 16, 4});
        } else if (Arrays.areEqual(this.f270H, bArr)) {
            return;
        }
        this.f270H = Arrays.clone(bArr);
        GCMUtil.asInts(bArr, this.f271M[1][8]);
        for (i = 4; i >= 1; i >>= 1) {
            GCMUtil.multiplyP(this.f271M[1][i + i], this.f271M[1][i]);
        }
        GCMUtil.multiplyP(this.f271M[1][1], this.f271M[0][8]);
        for (i = 4; i >= 1; i >>= 1) {
            GCMUtil.multiplyP(this.f271M[0][i + i], this.f271M[0][i]);
        }
        i = 0;
        while (true) {
            int i2;
            for (int i3 = 2; i3 < 16; i3 += i3) {
                for (i2 = 1; i2 < i3; i2++) {
                    GCMUtil.xor(this.f271M[i][i3], this.f271M[i][i2], this.f271M[i][i3 + i2]);
                }
            }
            i++;
            if (i == 32) {
                return;
            }
            if (i > 1) {
                for (i2 = 8; i2 > 0; i2 >>= 1) {
                    GCMUtil.multiplyP8(this.f271M[i - 2][i2], this.f271M[i][i2]);
                }
            }
        }
    }

    public void multiplyH(byte[] bArr) {
        int[] iArr = new int[4];
        for (int i = 15; i >= 0; i--) {
            int[] iArr2 = this.f271M[i + i][bArr[i] & 15];
            iArr[0] = iArr[0] ^ iArr2[0];
            iArr[1] = iArr[1] ^ iArr2[1];
            iArr[2] = iArr[2] ^ iArr2[2];
            iArr[3] = iArr2[3] ^ iArr[3];
            iArr2 = this.f271M[(i + i) + 1][(bArr[i] & 240) >>> 4];
            iArr[0] = iArr[0] ^ iArr2[0];
            iArr[1] = iArr[1] ^ iArr2[1];
            iArr[2] = iArr[2] ^ iArr2[2];
            iArr[3] = iArr2[3] ^ iArr[3];
        }
        Pack.intToBigEndian(iArr, bArr, 0);
    }
}
