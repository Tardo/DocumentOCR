package es.gob.jmulticard.ui.passwordcallback;

public final class NoAndroidDialogException extends RuntimeException {
    private static final long serialVersionUID = 2731900485282723772L;

    public NoAndroidDialogException() {
        super("Debe facilitar un gestor de diálogos no nulo a traves de PasswordCallbackManager.setDialogUIHandler() para el uso en dispositivos Android");
    }
}
