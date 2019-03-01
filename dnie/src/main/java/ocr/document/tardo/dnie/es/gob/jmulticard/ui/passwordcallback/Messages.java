package es.gob.jmulticard.ui.passwordcallback;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

public final class Messages {
    private static ResourceBundle bundle = ResourceBundle.getBundle("properties/messages");

    private Messages() {
    }

    public static String getString(String codeString) {
        try {
            return bundle.getString(codeString);
        } catch (MissingResourceException e) {
            return "##ERROR## Cadena no disponible: " + codeString;
        }
    }
}
