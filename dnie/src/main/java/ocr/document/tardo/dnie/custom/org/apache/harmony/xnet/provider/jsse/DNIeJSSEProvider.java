package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public final class DNIeJSSEProvider extends Provider {
    private static final long serialVersionUID = 3075686092260669675L;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.DNIeJSSEProvider$1 */
    class C00551 implements PrivilegedAction<Void> {
        C00551() {
        }

        public Void run() {
            DNIeJSSEProvider.this.put("SSLContext.TLS", SSLContextImpl.class.getName());
            DNIeJSSEProvider.this.put("Alg.Alias.SSLContext.TLSv1", "TLS");
            DNIeJSSEProvider.this.put("KeyManagerFactory.X509", KeyManagerFactoryImpl.class.getName());
            DNIeJSSEProvider.this.put("TrustManagerFactory.X509", TrustManagerFactoryImpl.class.getName());
            return null;
        }
    }

    public DNIeJSSEProvider() {
        super("DnieHarmonyJSSE", 1.0d, "Adapted DNIe Harmony JSSE Provider");
        AccessController.doPrivileged(new C00551());
    }
}
