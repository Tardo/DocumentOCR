package de.tsenger.androsmex.iso7816;

public class SecureMessagingException extends Exception {
    public SecureMessagingException(String message) {
        super(message);
    }

    public SecureMessagingException(Throwable cause) {
        super(cause);
    }

    public SecureMessagingException(String message, Throwable cause) {
        super(message, cause);
    }
}
