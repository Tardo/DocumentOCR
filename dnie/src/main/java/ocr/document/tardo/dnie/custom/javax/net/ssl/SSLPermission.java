package custom.javax.net.ssl;

import java.security.BasicPermission;

public final class SSLPermission extends BasicPermission {
    private static final long serialVersionUID = -3456898025505876775L;

    public SSLPermission(String name) {
        super(name);
    }

    public SSLPermission(String name, String actions) {
        super(name, actions);
    }
}
