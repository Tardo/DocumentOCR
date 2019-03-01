package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;
import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator {
    private Vector lookupPowX2;

    private void ensureAvailable(int i) {
        int size = this.lookupPowX2.size();
        if (size <= i) {
            byte[] bArr = (byte[]) this.lookupPowX2.elementAt(size - 1);
            do {
                bArr = Arrays.clone(bArr);
                GCMUtil.multiply(bArr, bArr);
                this.lookupPowX2.addElement(bArr);
                size++;
            } while (size <= i);
        }
    }

    public void exponentiateX(long j, byte[] bArr) {
        Object oneAsBytes = GCMUtil.oneAsBytes();
        int i = 0;
        while (j > 0) {
            if ((1 & j) != 0) {
                ensureAvailable(i);
                GCMUtil.multiply(oneAsBytes, (byte[]) this.lookupPowX2.elementAt(i));
            }
            j >>>= 1;
            i++;
        }
        System.arraycopy(oneAsBytes, 0, bArr, 0, 16);
    }

    public void init(byte[] bArr) {
        if (this.lookupPowX2 == null || !Arrays.areEqual(bArr, (byte[]) this.lookupPowX2.elementAt(0))) {
            this.lookupPowX2 = new Vector(8);
            this.lookupPowX2.addElement(Arrays.clone(bArr));
        }
    }
}
