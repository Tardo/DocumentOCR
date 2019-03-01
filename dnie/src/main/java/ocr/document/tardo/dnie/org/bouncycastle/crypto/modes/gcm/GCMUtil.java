package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.Arrays;

abstract class GCMUtil {
    GCMUtil() {
    }

    static byte[] asBytes(int[] iArr) {
        byte[] bArr = new byte[16];
        Pack.intToBigEndian(iArr, bArr, 0);
        return bArr;
    }

    static void asInts(byte[] bArr, int[] iArr) {
        Pack.bigEndianToInt(bArr, 0, iArr);
    }

    static int[] asInts(byte[] bArr) {
        int[] iArr = new int[4];
        Pack.bigEndianToInt(bArr, 0, iArr);
        return iArr;
    }

    static void multiply(byte[] bArr, byte[] bArr2) {
        byte[] clone = Arrays.clone(bArr);
        byte[] bArr3 = new byte[16];
        for (int i = 0; i < 16; i++) {
            byte b = bArr2[i];
            for (int i2 = 7; i2 >= 0; i2--) {
                if (((1 << i2) & b) != 0) {
                    xor(bArr3, clone);
                }
                int i3 = (clone[15] & 1) != 0 ? 1 : 0;
                shiftRight(clone);
                if (i3 != 0) {
                    clone[0] = (byte) (clone[0] ^ -31);
                }
            }
        }
        System.arraycopy(bArr3, 0, bArr, 0, 16);
    }

    static void multiplyP(int[] iArr) {
        int i = (iArr[3] & 1) != 0 ? 1 : 0;
        shiftRight(iArr);
        if (i != 0) {
            iArr[0] = iArr[0] ^ -520093696;
        }
    }

    static void multiplyP(int[] iArr, int[] iArr2) {
        int i = (iArr[3] & 1) != 0 ? 1 : 0;
        shiftRight(iArr, iArr2);
        if (i != 0) {
            iArr2[0] = iArr2[0] ^ -520093696;
        }
    }

    static void multiplyP8(int[] iArr) {
        int i = iArr[3];
        shiftRightN(iArr, 8);
        for (int i2 = 7; i2 >= 0; i2--) {
            if (((1 << i2) & i) != 0) {
                iArr[0] = iArr[0] ^ (-520093696 >>> (7 - i2));
            }
        }
    }

    static void multiplyP8(int[] iArr, int[] iArr2) {
        int i = iArr[3];
        shiftRightN(iArr, 8, iArr2);
        for (int i2 = 7; i2 >= 0; i2--) {
            if (((1 << i2) & i) != 0) {
                iArr2[0] = iArr2[0] ^ (-520093696 >>> (7 - i2));
            }
        }
    }

    static byte[] oneAsBytes() {
        byte[] bArr = new byte[16];
        bArr[0] = Byte.MIN_VALUE;
        return bArr;
    }

    static int[] oneAsInts() {
        int[] iArr = new int[4];
        iArr[0] = Integer.MIN_VALUE;
        return iArr;
    }

    static void shiftRight(byte[] bArr) {
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = bArr[i2] & 255;
            bArr[i2] = (byte) (i | (i3 >>> 1));
            i2++;
            if (i2 != 16) {
                i = (i3 & 1) << 7;
            } else {
                return;
            }
        }
    }

    static void shiftRight(byte[] bArr, byte[] bArr2) {
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = bArr[i2] & 255;
            bArr2[i2] = (byte) (i | (i3 >>> 1));
            i2++;
            if (i2 != 16) {
                i = (i3 & 1) << 7;
            } else {
                return;
            }
        }
    }

    static void shiftRight(int[] iArr) {
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = iArr[i2];
            iArr[i2] = i | (i3 >>> 1);
            i2++;
            if (i2 != 4) {
                i = i3 << 31;
            } else {
                return;
            }
        }
    }

    static void shiftRight(int[] iArr, int[] iArr2) {
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = iArr[i2];
            iArr2[i2] = i | (i3 >>> 1);
            i2++;
            if (i2 != 4) {
                i = i3 << 31;
            } else {
                return;
            }
        }
    }

    static void shiftRightN(int[] iArr, int i) {
        int i2 = 0;
        int i3 = 0;
        while (true) {
            int i4 = iArr[i3];
            iArr[i3] = i2 | (i4 >>> i);
            i3++;
            if (i3 != 4) {
                i2 = i4 << (32 - i);
            } else {
                return;
            }
        }
    }

    static void shiftRightN(int[] iArr, int i, int[] iArr2) {
        int i2 = 0;
        int i3 = 0;
        while (true) {
            int i4 = iArr[i3];
            iArr2[i3] = i2 | (i4 >>> i);
            i3++;
            if (i3 != 4) {
                i2 = i4 << (32 - i);
            } else {
                return;
            }
        }
    }

    static void xor(byte[] bArr, byte[] bArr2) {
        for (int i = 15; i >= 0; i--) {
            bArr[i] = (byte) (bArr[i] ^ bArr2[i]);
        }
    }

    static void xor(byte[] bArr, byte[] bArr2, int i, int i2) {
        while (true) {
            int i3 = i2 - 1;
            if (i2 > 0) {
                bArr[i3] = (byte) (bArr[i3] ^ bArr2[i + i3]);
                i2 = i3;
            } else {
                return;
            }
        }
    }

    static void xor(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        for (int i = 15; i >= 0; i--) {
            bArr3[i] = (byte) (bArr[i] ^ bArr2[i]);
        }
    }

    static void xor(int[] iArr, int[] iArr2) {
        for (int i = 3; i >= 0; i--) {
            iArr[i] = iArr[i] ^ iArr2[i];
        }
    }

    static void xor(int[] iArr, int[] iArr2, int[] iArr3) {
        for (int i = 3; i >= 0; i--) {
            iArr3[i] = iArr[i] ^ iArr2[i];
        }
    }
}
