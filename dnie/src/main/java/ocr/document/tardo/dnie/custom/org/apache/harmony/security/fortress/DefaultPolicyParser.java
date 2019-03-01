package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.DefaultPolicyScanner;
import custom.org.apache.harmony.security.DefaultPolicyScanner.GrantEntry;
import custom.org.apache.harmony.security.DefaultPolicyScanner.KeystoreEntry;
import custom.org.apache.harmony.security.DefaultPolicyScanner.PermissionEntry;
import custom.org.apache.harmony.security.DefaultPolicyScanner.PrincipalEntry;
import custom.org.apache.harmony.security.PolicyEntry;
import custom.org.apache.harmony.security.UnresolvedPrincipal;
import custom.org.apache.harmony.security.fortress.PolicyUtils.ExpansionFailedException;
import custom.org.apache.harmony.security.fortress.PolicyUtils.GeneralExpansionHandler;
import custom.org.apache.harmony.security.fortress.PolicyUtils.URLLoader;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Permission;
import java.security.Principal;
import java.security.UnresolvedPermission;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

public class DefaultPolicyParser {
    private final DefaultPolicyScanner scanner;

    class PermissionExpander implements GeneralExpansionHandler {
        private GrantEntry ge;
        private KeyStore ks;

        PermissionExpander() {
        }

        public PermissionExpander configure(GrantEntry ge, KeyStore ks) {
            this.ge = ge;
            this.ks = ks;
            return this;
        }

        public String resolve(String protocol, String data) throws ExpansionFailedException {
            if ("self".equals(protocol)) {
                if (this.ge.principals == null || this.ge.principals.size() == 0) {
                    throw new ExpansionFailedException(Messages.getString("security.144"));
                }
                StringBuilder sb = new StringBuilder();
                for (PrincipalEntry pr : this.ge.principals) {
                    if (pr.klass == null) {
                        try {
                            sb.append(pc2str(DefaultPolicyParser.this.getPrincipalByAlias(this.ks, pr.name)));
                        } catch (Exception e) {
                            throw new ExpansionFailedException(Messages.getString("security.143", pr.name), e);
                        }
                    }
                    sb.append(pr.klass).append(" \"").append(pr.name).append("\" ");
                }
                return sb.toString();
            } else if ("alias".equals(protocol)) {
                try {
                    return pc2str(DefaultPolicyParser.this.getPrincipalByAlias(this.ks, data));
                } catch (Exception e2) {
                    throw new ExpansionFailedException(Messages.getString("security.143", (Object) data), e2);
                }
            } else {
                throw new ExpansionFailedException(Messages.getString("security.145", (Object) protocol));
            }
        }

        private String pc2str(Principal pc) {
            String klass = pc.getClass().getName();
            String name = pc.getName();
            return new StringBuilder((klass.length() + name.length()) + 5).append(klass).append(" \"").append(name).append("\"").toString();
        }
    }

    public DefaultPolicyParser() {
        this.scanner = new DefaultPolicyScanner();
    }

    public DefaultPolicyParser(DefaultPolicyScanner s) {
        this.scanner = s;
    }

    public Collection<PolicyEntry> parse(URL location, Properties system) throws Exception {
        boolean resolve = PolicyUtils.canExpandProperties();
        Reader r = new BufferedReader(new InputStreamReader((InputStream) AccessController.doPrivileged(new URLLoader(location))));
        Collection<GrantEntry> grantEntries = new HashSet();
        List<KeystoreEntry> keystores = new ArrayList();
        try {
            this.scanner.scanStream(r, grantEntries, keystores);
            KeyStore ks = initKeyStore(keystores, location, system, resolve);
            Collection<PolicyEntry> result = new HashSet();
            for (GrantEntry ge : grantEntries) {
                try {
                    PolicyEntry pe = resolveGrant(ge, ks, system, resolve);
                    if (!pe.isVoid()) {
                        result.add(pe);
                    }
                } catch (Exception e) {
                }
            }
            return result;
        } finally {
            r.close();
        }
    }

    protected PolicyEntry resolveGrant(GrantEntry ge, KeyStore ks, Properties system, boolean resolve) throws Exception {
        URL codebase = null;
        Certificate[] signers = null;
        Set<Principal> principals = new HashSet();
        Set<Permission> permissions = new HashSet();
        if (ge.codebase != null) {
            codebase = new URL(resolve ? PolicyUtils.expandURL(ge.codebase, system) : ge.codebase);
        }
        if (ge.signers != null) {
            if (resolve) {
                ge.signers = PolicyUtils.expand(ge.signers, system);
            }
            signers = resolveSigners(ks, ge.signers);
        }
        if (ge.principals != null) {
            for (PrincipalEntry pe : ge.principals) {
                if (resolve) {
                    pe.name = PolicyUtils.expand(pe.name, system);
                }
                if (pe.klass == null) {
                    principals.add(getPrincipalByAlias(ks, pe.name));
                } else {
                    principals.add(new UnresolvedPrincipal(pe.klass, pe.name));
                }
            }
        }
        if (ge.permissions != null) {
            for (PermissionEntry pe2 : ge.permissions) {
                try {
                    permissions.add(resolvePermission(pe2, ge, ks, system, resolve));
                } catch (Exception e) {
                }
            }
        }
        return new PolicyEntry(new CodeSource(codebase, signers), principals, permissions);
    }

    protected Permission resolvePermission(PermissionEntry pe, GrantEntry ge, KeyStore ks, Properties system, boolean resolve) throws Exception {
        if (pe.name != null) {
            pe.name = PolicyUtils.expandGeneral(pe.name, new PermissionExpander().configure(ge, ks));
        }
        if (resolve) {
            if (pe.name != null) {
                pe.name = PolicyUtils.expand(pe.name, system);
            }
            if (pe.actions != null) {
                pe.actions = PolicyUtils.expand(pe.actions, system);
            }
            if (pe.signers != null) {
                pe.signers = PolicyUtils.expand(pe.signers, system);
            }
        }
        Certificate[] signers = pe.signers == null ? null : resolveSigners(ks, pe.signers);
        try {
            Class<?> klass = Class.forName(pe.klass);
            if (PolicyUtils.matchSubset(signers, klass.getSigners())) {
                return PolicyUtils.instantiatePermission(klass, pe.name, pe.actions);
            }
        } catch (ClassNotFoundException e) {
        }
        return new UnresolvedPermission(pe.klass, pe.name, pe.actions, signers);
    }

    protected Certificate[] resolveSigners(KeyStore ks, String signers) throws Exception {
        if (ks == null) {
            throw new KeyStoreException(Messages.getString("security.146", (Object) signers));
        }
        Collection<Certificate> certs = new HashSet();
        StringTokenizer snt = new StringTokenizer(signers, ",");
        while (snt.hasMoreTokens()) {
            certs.add(ks.getCertificate(snt.nextToken().trim()));
        }
        return (Certificate[]) certs.toArray(new Certificate[certs.size()]);
    }

    protected Principal getPrincipalByAlias(KeyStore ks, String alias) throws KeyStoreException, CertificateException {
        if (ks == null) {
            throw new KeyStoreException(Messages.getString("security.147", (Object) alias));
        }
        Certificate x509 = ks.getCertificate(alias);
        if (x509 instanceof X509Certificate) {
            return ((X509Certificate) x509).getSubjectX500Principal();
        }
        throw new CertificateException(Messages.getString("security.148", alias, x509));
    }

    protected KeyStore initKeyStore(List<KeystoreEntry> keystores, URL base, Properties system, boolean resolve) {
        int i = 0;
        while (i < keystores.size()) {
            InputStream is;
            try {
                KeystoreEntry ke = (KeystoreEntry) keystores.get(i);
                if (resolve) {
                    ke.url = PolicyUtils.expandURL(ke.url, system);
                    if (ke.type != null) {
                        ke.type = PolicyUtils.expand(ke.type, system);
                    }
                }
                if (ke.type == null || ke.type.length() == 0) {
                    ke.type = KeyStore.getDefaultType();
                }
                KeyStore ks = KeyStore.getInstance(ke.type);
                is = (InputStream) AccessController.doPrivileged(new URLLoader(new URL(base, ke.url)));
                ks.load(is, null);
                is.close();
                return ks;
            } catch (Exception e) {
                i++;
            } catch (Throwable th) {
                is.close();
            }
        }
        return null;
    }
}
