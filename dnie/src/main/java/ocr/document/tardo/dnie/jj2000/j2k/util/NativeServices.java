package jj2000.j2k.util;

public final class NativeServices {
    private static final int LIB_STATE_LOADED = 1;
    private static final int LIB_STATE_NOT_FOUND = 2;
    private static final int LIB_STATE_NOT_LOADED = 0;
    public static final String SHLIB_NAME = "jj2000";
    private static int libState;

    private static native int getThreadConcurrencyN();

    private static native void setThreadConcurrencyN(int i);

    private NativeServices() {
        throw new IllegalArgumentException("Class can not be instantiated");
    }

    public static void setThreadConcurrency(int n) {
        checkLibrary();
        if (n < 0) {
            throw new IllegalArgumentException();
        }
        setThreadConcurrencyN(n);
    }

    public static int getThreadConcurrency() {
        checkLibrary();
        return getThreadConcurrencyN();
    }

    public static boolean loadLibrary() {
        if (libState == 1) {
            return true;
        }
        try {
            System.loadLibrary(SHLIB_NAME);
            libState = 1;
            return true;
        } catch (UnsatisfiedLinkError e) {
            libState = 2;
            return false;
        }
    }

    private static void checkLibrary() {
        switch (libState) {
            case 0:
                if (loadLibrary()) {
                    return;
                }
                break;
            case 2:
                break;
            default:
                return;
        }
        throw new UnsatisfiedLinkError("NativeServices: native shared library could not be loaded");
    }
}
