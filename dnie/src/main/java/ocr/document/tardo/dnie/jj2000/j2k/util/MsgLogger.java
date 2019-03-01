package jj2000.j2k.util;

public interface MsgLogger {
    public static final int ERROR = 3;
    public static final int INFO = 1;
    public static final int LOG = 0;
    public static final int WARNING = 2;

    void flush();

    void println(String str, int i, int i2);

    void printmsg(int i, String str);
}
