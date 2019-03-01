package org.bouncycastle.crypto.prng.drbg;

import java.util.Hashtable;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.Integers;

class Utils {
    static final Hashtable maxSecurityStrengths = new Hashtable();

    static {
        maxSecurityStrengths.put("SHA-1", Integers.valueOf(128));
        maxSecurityStrengths.put("SHA-224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-384", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-512/256", Integers.valueOf(256));
    }

    Utils() {
    }

    static int getMaxSecurityStrength(Digest digest) {
        return ((Integer) maxSecurityStrengths.get(digest.getAlgorithmName())).intValue();
    }

    static int getMaxSecurityStrength(Mac mac) {
        String algorithmName = mac.getAlgorithmName();
        return ((Integer) maxSecurityStrengths.get(algorithmName.substring(0, algorithmName.indexOf("/")))).intValue();
    }

    static byte[] hash_df(Digest digest, byte[] bArr, int i) {
        int i2;
        int i3 = 0;
        Object obj = new byte[((i + 7) / 8)];
        int length = obj.length / digest.getDigestSize();
        Object obj2 = new byte[digest.getDigestSize()];
        int i4 = 1;
        for (i2 = 0; i2 <= length; i2++) {
            digest.update((byte) i4);
            digest.update((byte) (i >> 24));
            digest.update((byte) (i >> 16));
            digest.update((byte) (i >> 8));
            digest.update((byte) i);
            digest.update(bArr, 0, bArr.length);
            digest.doFinal(obj2, 0);
            System.arraycopy(obj2, 0, obj, obj2.length * i2, obj.length - (obj2.length * i2) > obj2.length ? obj2.length : obj.length - (obj2.length * i2));
            i4++;
        }
        if (i % 8 != 0) {
            i4 = 8 - (i % 8);
            int i5 = 0;
            while (i5 != obj.length) {
                i2 = obj[i5] & 255;
                obj[i5] = (byte) ((i3 << (8 - i4)) | (i2 >>> i4));
                i5++;
                i3 = i2;
            }
        }
        return obj;
    }

    static boolean isTooLarge(byte[] bArr, int i) {
        return bArr != null && bArr.length > i;
    }
}
