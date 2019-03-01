package org.spongycastle.jce;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.StringTokenizer;
import org.spongycastle.util.Strings;

public class ProviderConfigurationPermission extends BasicPermission {
    private static final int ALL = 3;
    private static final String ALL_STR = "all";
    private static final int EC_IMPLICITLY_CA = 2;
    private static final String EC_IMPLICITLY_CA_STR = "ecimplicitlyca";
    private static final int THREAD_LOCAL_EC_IMPLICITLY_CA = 1;
    private static final String THREAD_LOCAL_EC_IMPLICITLY_CA_STR = "threadlocalecimplicitlyca";
    private final String actions;
    private final int permissionMask;

    public ProviderConfigurationPermission(String name) {
        super(name);
        this.actions = ALL_STR;
        this.permissionMask = 3;
    }

    public ProviderConfigurationPermission(String name, String actions) {
        super(name, actions);
        this.actions = actions;
        this.permissionMask = calculateMask(actions);
    }

    private int calculateMask(String actions) {
        StringTokenizer tok = new StringTokenizer(Strings.toLowerCase(actions), " ,");
        int mask = 0;
        while (tok.hasMoreTokens()) {
            String s = tok.nextToken();
            if (s.equals(THREAD_LOCAL_EC_IMPLICITLY_CA_STR)) {
                mask |= 1;
            } else if (s.equals(EC_IMPLICITLY_CA_STR)) {
                mask |= 2;
            } else if (s.equals(ALL_STR)) {
                mask |= 3;
            }
        }
        if (mask != 0) {
            return mask;
        }
        throw new IllegalArgumentException("unknown permissions passed to mask");
    }

    public String getActions() {
        return this.actions;
    }

    public boolean implies(Permission permission) {
        if (!(permission instanceof ProviderConfigurationPermission) || !getName().equals(permission.getName())) {
            return false;
        }
        ProviderConfigurationPermission other = (ProviderConfigurationPermission) permission;
        if ((this.permissionMask & other.permissionMask) == other.permissionMask) {
            return true;
        }
        return false;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ProviderConfigurationPermission)) {
            return false;
        }
        ProviderConfigurationPermission other = (ProviderConfigurationPermission) obj;
        if (this.permissionMask == other.permissionMask && getName().equals(other.getName())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return getName().hashCode() + this.permissionMask;
    }
}
