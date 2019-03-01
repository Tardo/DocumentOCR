package de.tsenger.androsmex.pace;

public class PaceException extends Exception {
    public PaceException(String message) {
        super(message);
    }

    public PaceException(Throwable cause) {
        super(cause);
    }

    public PaceException(String message, Throwable cause) {
        super(message, cause);
    }
}
