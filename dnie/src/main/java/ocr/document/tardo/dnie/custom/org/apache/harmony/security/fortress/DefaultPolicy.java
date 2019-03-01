package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.PolicyEntry;
import custom.org.apache.harmony.security.fortress.PolicyUtils.SystemKit;
import java.io.File;
import java.net.URL;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.WeakHashMap;

public class DefaultPolicy extends Policy {
    public static final String JAVA_SECURITY_POLICY = "java.security.policy";
    public static final String POLICY_URL_PREFIX = "policy.url.";
    private final Map<Object, Collection<Permission>> cache;
    private final Set<PolicyEntry> grants;
    private boolean initialized;
    private final DefaultPolicyParser parser;

    public DefaultPolicy() {
        this(new DefaultPolicyParser());
    }

    public DefaultPolicy(DefaultPolicyParser dpr) {
        this.grants = new HashSet();
        this.cache = new WeakHashMap();
        this.parser = dpr;
        this.initialized = false;
        refresh();
    }

    public PermissionCollection getPermissions(ProtectionDomain pd) {
        Throwable th;
        if (!this.initialized) {
            synchronized (this) {
                if (!this.initialized) {
                    refresh();
                }
            }
        }
        Collection<Permission> pc = (Collection) this.cache.get(pd);
        if (pc == null) {
            synchronized (this.cache) {
                pc = (Collection) this.cache.get(pd);
                if (pc == null) {
                    Collection<Permission> pc2 = new HashSet();
                    try {
                        for (PolicyEntry ge : this.grants) {
                            if (ge.impliesPrincipals(pd == null ? null : pd.getPrincipals())) {
                                if (ge.impliesCodeSource(pd == null ? null : pd.getCodeSource())) {
                                    pc2.addAll(ge.getPermissions());
                                }
                            }
                        }
                        this.cache.put(pd, pc2);
                        pc = pc2;
                    } catch (Throwable th2) {
                        th = th2;
                        pc = pc2;
                    }
                }
                try {
                } catch (Throwable th3) {
                    th = th3;
                    throw th;
                }
            }
        }
        return PolicyUtils.toPermissionCollection(pc);
    }

    public PermissionCollection getPermissions(CodeSource cs) {
        Throwable th;
        if (!this.initialized) {
            synchronized (this) {
                if (!this.initialized) {
                    refresh();
                }
            }
        }
        Collection<Permission> pc = (Collection) this.cache.get(cs);
        if (pc == null) {
            synchronized (this.cache) {
                pc = (Collection) this.cache.get(cs);
                if (pc == null) {
                    Collection<Permission> pc2 = new HashSet();
                    try {
                        for (PolicyEntry ge : this.grants) {
                            if (ge.impliesPrincipals(null) && ge.impliesCodeSource(cs)) {
                                pc2.addAll(ge.getPermissions());
                            }
                        }
                        this.cache.put(cs, pc2);
                        pc = pc2;
                    } catch (Throwable th2) {
                        th = th2;
                        pc = pc2;
                        throw th;
                    }
                }
                try {
                } catch (Throwable th3) {
                    th = th3;
                    throw th;
                }
            }
        }
        return PolicyUtils.toPermissionCollection(pc);
    }

    public synchronized void refresh() {
        Set<PolicyEntry> fresh = new HashSet();
        Properties system = new Properties((Properties) AccessController.doPrivileged(new SystemKit()));
        system.setProperty("/", File.separator);
        URL[] policyLocations = PolicyUtils.getPolicyURLs(system, JAVA_SECURITY_POLICY, POLICY_URL_PREFIX);
        for (URL parse : policyLocations) {
            try {
                fresh.addAll(this.parser.parse(parse, system));
            } catch (Exception e) {
            }
        }
        synchronized (this.cache) {
            this.grants.clear();
            this.grants.addAll(fresh);
            this.cache.clear();
        }
        this.initialized = true;
    }
}
