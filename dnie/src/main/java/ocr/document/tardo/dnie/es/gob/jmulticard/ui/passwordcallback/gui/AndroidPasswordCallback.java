package es.gob.jmulticard.ui.passwordcallback.gui;

import es.gob.jmulticard.ui.passwordcallback.CancelledOperationException;
import es.gob.jmulticard.ui.passwordcallback.DialogUIHandler;
import javax.security.auth.callback.PasswordCallback;

public final class AndroidPasswordCallback extends PasswordCallback {
    private static final long serialVersionUID = 1;
    private String thePrompt;
    private int theRetries;
    private String theTitle;
    private DialogUIHandler uiHandler;

    protected AndroidPasswordCallback(DialogUIHandler dialogUIHandler, String prompt, String title, int retries) {
        super(prompt, true);
        this.theTitle = title;
        this.thePrompt = prompt;
        this.uiHandler = dialogUIHandler;
        this.theRetries = retries;
        setPassword(getPassword());
    }

    public AndroidPasswordCallback() {
        super("Introduzca PIN: ", true);
    }

    public char[] getPassword() {
        char[] pass = super.getPassword();
        if (pass != null && pass.length > 0) {
            return pass;
        }
        pass = this.uiHandler.showPasswordDialog(this.theRetries);
        if (pass != null) {
            return pass;
        }
        throw new CancelledOperationException("Operacion cancelada por el usuario.\nNo se ha proporcionado ninguna contraseña.");
    }

    public void clearPassword() {
        super.clearPassword();
        setPassword(null);
    }
}
