package es.gob.jmulticard.ui.passwordcallback;

public final class DNIeDialogManager {
    private static DialogUIHandler dialogUIHandler = null;

    public static DialogUIHandler getDialogUIHandler() {
        return dialogUIHandler;
    }

    public static void setDialogUIHandler(DialogUIHandler dialogUIHandler) {
        dialogUIHandler = dialogUIHandler;
    }

    private DNIeDialogManager() {
    }
}
