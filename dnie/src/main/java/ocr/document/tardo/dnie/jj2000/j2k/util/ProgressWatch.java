package jj2000.j2k.util;

public interface ProgressWatch {
    void initProgressWatch(int i, int i2, String str);

    void terminateProgressWatch();

    void updateProgressWatch(int i, String str);
}
