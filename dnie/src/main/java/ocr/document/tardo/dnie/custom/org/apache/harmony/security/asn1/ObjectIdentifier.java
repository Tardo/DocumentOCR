package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.util.Arrays;

public final class ObjectIdentifier {
    private final int[] oid;
    private String soid;

    public ObjectIdentifier(int[] oid) {
        validate(oid);
        this.oid = oid;
    }

    public ObjectIdentifier(String strOid) {
        this.oid = toIntArray(strOid);
        this.soid = strOid;
    }

    public int[] getOid() {
        return this.oid;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return Arrays.equals(this.oid, ((ObjectIdentifier) o).oid);
    }

    public String toString() {
        if (this.soid == null) {
            this.soid = toString(this.oid);
        }
        return this.soid;
    }

    public int hashCode() {
        int intHash = 0;
        int i = 0;
        while (i < this.oid.length && i < 4) {
            intHash += this.oid[i] << (i * 8);
            i++;
        }
        return Integer.MAX_VALUE & intHash;
    }

    public static void validate(int[] oid) {
        if (oid == null) {
            throw new IllegalArgumentException(Messages.getString("security.98"));
        } else if (oid.length < 2) {
            throw new IllegalArgumentException(Messages.getString("security.99"));
        } else if (oid[0] > 2) {
            throw new IllegalArgumentException(Messages.getString("security.9A"));
        } else if (oid[0] == 2 || oid[1] <= 39) {
            for (int i : oid) {
                if (i < 0) {
                    throw new IllegalArgumentException(Messages.getString("security.9C"));
                }
            }
        } else {
            throw new IllegalArgumentException(Messages.getString("security.9B"));
        }
    }

    public static String toString(int[] oid) {
        StringBuilder sb = new StringBuilder(oid.length * 3);
        for (int i = 0; i < oid.length - 1; i++) {
            sb.append(oid[i]);
            sb.append('.');
        }
        sb.append(oid[oid.length - 1]);
        return sb.toString();
    }

    public static int[] toIntArray(String str) {
        if (str == null) {
            throw new IllegalArgumentException(Messages.getString("security.9D"));
        }
        int length = str.length();
        if (length == 0) {
            throw new IllegalArgumentException(Messages.getString("security.9E"));
        }
        int i;
        int count = 1;
        boolean wasDot = true;
        for (i = 0; i < length; i++) {
            char c = str.charAt(i);
            if (c == '.') {
                if (wasDot) {
                    throw new IllegalArgumentException(Messages.getString("security.9E"));
                }
                wasDot = true;
                count++;
            } else if (c < '0' || c > '9') {
                throw new IllegalArgumentException(Messages.getString("security.9E"));
            } else {
                wasDot = false;
            }
        }
        if (wasDot) {
            throw new IllegalArgumentException(Messages.getString("security.9E"));
        } else if (count < 2) {
            throw new IllegalArgumentException(Messages.getString("security.99"));
        } else {
            int[] oid = new int[count];
            int j = 0;
            for (i = 0; i < length; i++) {
                c = str.charAt(i);
                if (c == '.') {
                    j++;
                } else {
                    oid[j] = ((oid[j] * 10) + c) - 48;
                }
            }
            if (oid[0] > 2) {
                throw new IllegalArgumentException(Messages.getString("security.9A"));
            } else if (oid[0] == 2 || oid[1] <= 39) {
                return oid;
            } else {
                throw new IllegalArgumentException(Messages.getString("security.9B"));
            }
        }
    }
}
