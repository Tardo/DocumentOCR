package custom.org.apache.harmony.security;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.Identity;
import java.security.IdentityScope;
import java.security.KeyManagementException;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Hashtable;

public class SystemScope extends IdentityScope {
    private static final long serialVersionUID = -4810285697932522607L;
    private Hashtable keys = new Hashtable();
    private Hashtable names = new Hashtable();

    public SystemScope(String name) {
        super(name);
    }

    public SystemScope(String name, IdentityScope scope) throws KeyManagementException {
        super(name, scope);
    }

    public int size() {
        return this.names.size();
    }

    public synchronized Identity getIdentity(String name) {
        if (name == null) {
            throw new NullPointerException();
        }
        return (Identity) this.names.get(name);
    }

    public synchronized Identity getIdentity(PublicKey key) {
        Identity identity;
        if (key == null) {
            identity = null;
        } else {
            identity = (Identity) this.keys.get(key);
        }
        return identity;
    }

    public synchronized void addIdentity(Identity identity) throws KeyManagementException {
        if (identity == null) {
            throw new NullPointerException(Messages.getString("security.92"));
        }
        Object name = identity.getName();
        if (this.names.containsKey(name)) {
            throw new KeyManagementException(Messages.getString("security.93", name));
        }
        Object key = identity.getPublicKey();
        if (key == null || !this.keys.containsKey(key)) {
            this.names.put(name, identity);
            if (key != null) {
                this.keys.put(key, identity);
            }
        } else {
            throw new KeyManagementException(Messages.getString("security.94", key));
        }
    }

    public synchronized void removeIdentity(Identity identity) throws KeyManagementException {
        if (identity == null) {
            throw new NullPointerException(Messages.getString("security.92"));
        }
        String name = identity.getName();
        if (name == null) {
            throw new NullPointerException(Messages.getString("security.95"));
        }
        boolean contains = this.names.containsKey(name);
        this.names.remove(name);
        PublicKey key = identity.getPublicKey();
        if (key != null) {
            contains = contains || this.keys.containsKey(key);
            this.keys.remove(key);
        }
        if (!contains) {
            throw new KeyManagementException(Messages.getString("security.96"));
        }
    }

    public Enumeration identities() {
        return this.names.elements();
    }
}
