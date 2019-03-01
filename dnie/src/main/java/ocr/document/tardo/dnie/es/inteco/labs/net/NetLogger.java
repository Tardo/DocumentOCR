package es.inteco.labs.net;

import android.util.Log;

public final class NetLogger {
    private NetLogger() {
    }

    /* renamed from: v */
    public static void m6v(Object message) {
        Log.v("iLabsNet", String.valueOf(message));
    }

    /* renamed from: d */
    public static void m3d(Object message) {
        Log.d("iLabsNet", String.valueOf(message));
    }

    /* renamed from: i */
    public static void m5i(Object message) {
        Log.i("iLabsNet", String.valueOf(message));
    }

    /* renamed from: w */
    public static void m7w(Object message) {
        Log.w("iLabsNet", String.valueOf(message));
    }

    /* renamed from: e */
    public static void m4e(Object message) {
        Log.e("iLabsNet", String.valueOf(message));
    }
}
