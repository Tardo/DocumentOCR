package jj2000.j2k.util;

import java.util.Hashtable;

public class FacilityManager {
    private static MsgLogger defMsgLogger = new StreamMsgLogger(System.out, System.err, 78);
    private static ProgressWatch defWatchProg = null;
    private static final Hashtable loggerList = new Hashtable();
    private static final Hashtable watchProgList = new Hashtable();

    public static void registerProgressWatch(Thread t, ProgressWatch pw) {
        if (pw == null) {
            throw new NullPointerException();
        } else if (t == null) {
            defWatchProg = pw;
        } else {
            watchProgList.put(t, pw);
        }
    }

    public static ProgressWatch getProgressWatch() {
        ProgressWatch pw = (ProgressWatch) watchProgList.get(Thread.currentThread());
        return pw == null ? defWatchProg : pw;
    }

    public static void registerMsgLogger(Thread t, MsgLogger ml) {
        if (ml == null) {
            throw new NullPointerException();
        } else if (t == null) {
            defMsgLogger = ml;
        } else {
            loggerList.put(t, ml);
        }
    }

    public static MsgLogger getMsgLogger() {
        MsgLogger ml = (MsgLogger) loggerList.get(Thread.currentThread());
        return ml == null ? defMsgLogger : ml;
    }

    public static MsgLogger getMsgLogger(Thread t) {
        MsgLogger ml = (MsgLogger) loggerList.get(t);
        return ml == null ? defMsgLogger : ml;
    }
}
