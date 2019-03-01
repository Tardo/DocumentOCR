package es.gob.jmulticard.ui.passwordcallback;

public interface DialogUIHandler {
    public static final int NO_OPTION = 1;
    public static final int YES_OPTION = 0;

    Object getAndroidContext();

    int showConfirmDialog(String str);

    char[] showPasswordDialog(int i);
}
