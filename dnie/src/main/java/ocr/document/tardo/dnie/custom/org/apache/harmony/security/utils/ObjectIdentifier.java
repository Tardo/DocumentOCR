package custom.org.apache.harmony.security.utils;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.util.Arrays;

public final class ObjectIdentifier {
    private Object group;
    private int hash;
    private String name;
    private final int[] oid;
    private String sOID;
    private String soid;

    public ObjectIdentifier(int[] oid) {
        this.hash = -1;
        validateOid(oid);
        this.oid = oid;
    }

    public ObjectIdentifier(int[] oid, String name, Object oidGroup) {
        this(oid);
        if (oidGroup == null) {
            throw new NullPointerException(Messages.getString("security.172"));
        }
        this.group = oidGroup;
        this.name = name;
        toOIDString();
    }

    public int[] getOid() {
        return this.oid;
    }

    public String getName() {
        return this.name;
    }

    public Object getGroup() {
        return this.group;
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

    public String toOIDString() {
        if (this.sOID == null) {
            this.sOID = "OID." + toString();
        }
        return this.sOID;
    }

    public String toString() {
        if (this.soid == null) {
            StringBuilder sb = new StringBuilder(this.oid.length * 4);
            for (int i = 0; i < this.oid.length - 1; i++) {
                sb.append(this.oid[i]);
                sb.append('.');
            }
            sb.append(this.oid[this.oid.length - 1]);
            this.soid = sb.toString();
        }
        return this.soid;
    }

    public int hashCode() {
        if (this.hash == -1) {
            this.hash = hashIntArray(this.oid);
        }
        return this.hash;
    }

    public static void validateOid(int[] oid) {
        if (oid == null) {
            throw new NullPointerException(Messages.getString("security.98"));
        } else if (oid.length < 2) {
            throw new IllegalArgumentException(Messages.getString("security.99"));
        } else if (oid[0] > 2) {
            throw new IllegalArgumentException(Messages.getString("security.9A"));
        } else if (oid[0] != 2 && oid[1] > 39) {
            throw new IllegalArgumentException(Messages.getString("security.9B"));
        }
    }

    public static int hashIntArray(int[] array) {
        int intHash = 0;
        int i = 0;
        while (i < array.length && i < 4) {
            intHash += array[i] << (i * 8);
            i++;
        }
        return Integer.MAX_VALUE & intHash;
    }
}
