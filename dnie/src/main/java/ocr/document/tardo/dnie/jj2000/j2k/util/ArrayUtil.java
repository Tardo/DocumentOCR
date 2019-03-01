package jj2000.j2k.util;

public class ArrayUtil {
    public static final int INIT_EL_COPYING = 4;
    public static final int MAX_EL_COPYING = 8;

    public static void intArraySet(int[] arr, int val) {
        int len = arr.length;
        int i;
        if (len < 8) {
            for (i = len - 1; i >= 0; i--) {
                arr[i] = val;
            }
            return;
        }
        int len2 = len >> 1;
        i = 0;
        while (i < 4) {
            arr[i] = val;
            i++;
        }
        while (i <= len2) {
            System.arraycopy(arr, 0, arr, i, i);
            i <<= 1;
        }
        if (i < len) {
            System.arraycopy(arr, 0, arr, i, len - i);
        }
    }

    public static void byteArraySet(byte[] arr, byte val) {
        int len = arr.length;
        int i;
        if (len < 8) {
            for (i = len - 1; i >= 0; i--) {
                arr[i] = val;
            }
            return;
        }
        int len2 = len >> 1;
        i = 0;
        while (i < 4) {
            arr[i] = val;
            i++;
        }
        while (i <= len2) {
            System.arraycopy(arr, 0, arr, i, i);
            i <<= 1;
        }
        if (i < len) {
            System.arraycopy(arr, 0, arr, i, len - i);
        }
    }
}
