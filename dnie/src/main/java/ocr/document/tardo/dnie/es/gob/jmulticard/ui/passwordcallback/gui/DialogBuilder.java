package es.gob.jmulticard.ui.passwordcallback.gui;

import es.gob.jmulticard.ui.passwordcallback.CancelledOperationException;
import es.gob.jmulticard.ui.passwordcallback.DNIeDialogManager;
import es.gob.jmulticard.ui.passwordcallback.DialogUIHandler;
import es.gob.jmulticard.ui.passwordcallback.NoAndroidDialogException;
import javax.security.auth.callback.PasswordCallback;

public final class DialogBuilder {
    private static DialogUIHandler midialog;

    private DialogBuilder() {
        midialog = null;
    }

    private DialogBuilder(DialogUIHandler dialog) {
        midialog = dialog;
    }

    public static int showSignatureConfirmDialog(boolean authenticationCert) throws Exception {
        midialog = DNIeDialogManager.getDialogUIHandler();
        if (midialog != null) {
            return midialog.showConfirmDialog("?Desea realizar firma digital con certificado de " + (authenticationCert ? "Autenticaci?n" : "Firma") + "?");
        }
        throw new CancelledOperationException();
    }

    public static PasswordCallback getDnieBadPinPasswordCallback(int retriesLeft) {
        midialog = DNIeDialogManager.getDialogUIHandler();
        if (midialog != null) {
            return new AndroidPasswordCallback(midialog, "PIN Incorrecto \n[" + Integer.toString(retriesLeft) + " reintentos]\nIntroduzca PIN: ", "DNI Electr?nico: Introducci?n de PIN", retriesLeft);
        }
        throw new NoAndroidDialogException();
    }

    public static PasswordCallback getDniePinForCertificateReadingPasswordCallback() {
        midialog = DNIeDialogManager.getDialogUIHandler();
        if (midialog != null) {
            return new AndroidPasswordCallback(midialog, "Introduzca PIN: ", "DNI Electronico: Firma electronica", -1);
        }
        throw new NoAndroidDialogException();
    }
}
