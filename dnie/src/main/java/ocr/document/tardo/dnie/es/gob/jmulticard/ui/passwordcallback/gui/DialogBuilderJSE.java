package es.gob.jmulticard.ui.passwordcallback.gui;

import es.gob.jmulticard.ui.passwordcallback.Messages;
import java.io.Console;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Locale;

public class DialogBuilderJSE {
    private static boolean headless = false;

    /* renamed from: es.gob.jmulticard.ui.passwordcallback.gui.DialogBuilderJSE$1 */
    static class C00821 implements PrivilegedAction<Void> {
        C00821() {
        }

        public Void run() {
            DialogBuilderJSE.setHeadLess(Boolean.getBoolean("java.awt.headless"));
            return null;
        }
    }

    static {
        AccessController.doPrivileged(new C00821());
    }

    static void setHeadLess(boolean hl) {
        headless = hl;
    }

    private DialogBuilderJSE() {
    }

    private static int getConsoleConfirm(Console console, boolean digitalSignCert) {
        console.printf((digitalSignCert ? Messages.getString("DialogBuilder.3") : Messages.getString("DialogBuilder.2")) + " " + Messages.getString("DialogBuilder.4") + "\n", new Object[0]);
        String confirm = console.readLine().replace("\n", "").replace("\r", "").trim().toLowerCase(Locale.getDefault());
        if ("si".equals(confirm) || "s".equals(confirm) || "sí".equals(confirm)) {
            return 0;
        }
        if ("no".equals(confirm) || "n".equals(confirm)) {
            return 1;
        }
        return getConsoleConfirm(console, digitalSignCert);
    }
}
