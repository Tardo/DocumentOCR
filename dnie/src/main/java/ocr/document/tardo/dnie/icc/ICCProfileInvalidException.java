package icc;

public class ICCProfileInvalidException extends ICCProfileException {
    ICCProfileInvalidException(String msg) {
        super(msg);
    }

    ICCProfileInvalidException() {
        super("icc profile is invalid");
    }
}
