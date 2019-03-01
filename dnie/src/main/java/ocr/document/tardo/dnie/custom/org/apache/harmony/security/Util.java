package custom.org.apache.harmony.security;

public class Util {
    public static String toUpperCase(String s) {
        return s.toUpperCase();
    }

    public static boolean equalsIgnoreCase(String s1, String s2) {
        return s1.toUpperCase().equals(s2.toUpperCase());
    }
}
