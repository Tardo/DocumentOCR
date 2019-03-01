package custom.org.apache.harmony.security;

import custom.org.apache.harmony.security.fortress.PolicyUtils;
import java.net.URL;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;

public class PolicyEntry {
    private final CodeSource cs;
    private final Collection<Permission> permissions;
    private final Principal[] principals;

    public PolicyEntry(CodeSource cs, Collection<? extends Principal> prs, Collection<? extends Permission> permissions) {
        Collection collection = null;
        this.cs = cs != null ? normalizeCodeSource(cs) : null;
        Principal[] principalArr = (prs == null || prs.isEmpty()) ? null : (Principal[]) prs.toArray(new Principal[prs.size()]);
        this.principals = principalArr;
        if (!(permissions == null || permissions.isEmpty())) {
            collection = Collections.unmodifiableCollection(permissions);
        }
        this.permissions = collection;
    }

    public boolean impliesCodeSource(CodeSource codeSource) {
        if (this.cs == null) {
            return true;
        }
        if (codeSource == null) {
            return false;
        }
        return this.cs.implies(normalizeCodeSource(codeSource));
    }

    private CodeSource normalizeCodeSource(CodeSource codeSource) {
        URL codeSourceURL = PolicyUtils.normalizeURL(codeSource.getLocation());
        CodeSource result = codeSource;
        if (codeSourceURL == codeSource.getLocation()) {
            return result;
        }
        CodeSigner[] signers = codeSource.getCodeSigners();
        if (signers == null) {
            return new CodeSource(codeSourceURL, codeSource.getCertificates());
        }
        return new CodeSource(codeSourceURL, signers);
    }

    public boolean impliesPrincipals(Principal[] prs) {
        return PolicyUtils.matchSubset(this.principals, prs);
    }

    public Collection<Permission> getPermissions() {
        return this.permissions;
    }

    public boolean isVoid() {
        return this.permissions == null || this.permissions.size() == 0;
    }
}
