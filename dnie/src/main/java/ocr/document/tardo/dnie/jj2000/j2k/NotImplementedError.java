package jj2000.j2k;

public class NotImplementedError extends Error {
    public NotImplementedError() {
        super("The called method has not been implemented yet. Sorry!");
    }

    public NotImplementedError(String m) {
        super(m);
    }
}
