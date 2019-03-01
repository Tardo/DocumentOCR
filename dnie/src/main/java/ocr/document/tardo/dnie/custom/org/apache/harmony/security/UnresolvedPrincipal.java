package custom.org.apache.harmony.security;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.Principal;

public final class UnresolvedPrincipal implements Principal {
    public static final String WILDCARD = "*";
    private final String klass;
    private final String name;

    public UnresolvedPrincipal(String klass, String name) {
        if (klass == null || klass.length() == 0) {
            throw new IllegalArgumentException(Messages.getString("security.91"));
        }
        this.klass = klass;
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public String getClassName() {
        return this.klass;
    }

    public boolean equals(Object that) {
        if (that instanceof UnresolvedPrincipal) {
            UnresolvedPrincipal up = (UnresolvedPrincipal) that;
            if (!this.klass.equals(up.klass)) {
                return false;
            }
            if (this.name == null) {
                if (up.name != null) {
                    return false;
                }
            } else if (!this.name.equals(up.name)) {
                return false;
            }
            return true;
        } else if (that instanceof Principal) {
            return implies((Principal) that);
        } else {
            return false;
        }
    }

    public boolean implies(Principal another) {
        return another != null && ("*".equals(this.klass) || (this.klass.equals(another.getClass().getName()) && ("*".equals(this.name) || (this.name != null ? this.name.equals(another.getName()) : another.getName() == null))));
    }

    public int hashCode() {
        int hash = 0;
        if (this.name != null) {
            hash = 0 ^ this.name.hashCode();
        }
        if (this.klass != null) {
            return hash ^ this.klass.hashCode();
        }
        return hash;
    }

    public String toString() {
        return "Principal " + this.klass + " \"" + this.name + "\"";
    }
}
