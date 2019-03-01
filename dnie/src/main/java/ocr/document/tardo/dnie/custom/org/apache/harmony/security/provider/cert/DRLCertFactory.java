package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public final class DRLCertFactory extends Provider {
    private static final long serialVersionUID = -7269650779605195879L;

    /* renamed from: custom.org.apache.harmony.security.provider.cert.DRLCertFactory$1 */
    class C00511 implements PrivilegedAction<Void> {
        C00511() {
        }

        public Void run() {
            DRLCertFactory.this.put("CertificateFactory.X509", "org.apache.harmony.security.provider.cert.X509CertFactoryImpl");
            DRLCertFactory.this.put("Alg.Alias.CertificateFactory.X.509", "X509");
            return null;
        }
    }

    public DRLCertFactory() {
        super("DRLCertFactory", 1.0d, Messages.getString("security.151"));
        AccessController.doPrivileged(new C00511());
    }
}
