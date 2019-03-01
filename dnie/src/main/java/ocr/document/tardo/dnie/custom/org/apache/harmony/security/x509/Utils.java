package custom.org.apache.harmony.security.x509;

import org.bouncycastle.pqc.math.linearalgebra.Matrix;

public class Utils {
    public static boolean isPrintableString(String str) {
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch != ' ' && ((ch < '\'' || ch > ')') && ((ch < '+' || ch > ':') && ch != '=' && ch != '?' && ((ch < 'A' || ch > Matrix.MATRIX_TYPE_ZERO) && (ch < 'a' || ch > 'z'))))) {
                return false;
            }
        }
        return true;
    }
}
