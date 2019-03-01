package jj2000.j2k;

public class JJ2KExceptionHandler {
    public static void handleException(Throwable e) {
        e.fillInStackTrace();
        e.printStackTrace();
        System.err.println("The Thread is being terminated bacause an Exception (shown above)\nhas been thrown and no special action was defined for this Thread.");
        throw new ThreadDeath();
    }
}
