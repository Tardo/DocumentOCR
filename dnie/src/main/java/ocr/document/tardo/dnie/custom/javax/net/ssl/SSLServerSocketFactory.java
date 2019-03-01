package custom.javax.net.ssl;

import custom.javax.net.ServerSocketFactory;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

public abstract class SSLServerSocketFactory extends ServerSocketFactory {
    private static String defaultName;
    private static ServerSocketFactory defaultServerSocketFactory;

    /* renamed from: custom.javax.net.ssl.SSLServerSocketFactory$1 */
    static class C00451 implements PrivilegedAction<Void> {
        C00451() {
        }

        public Void run() {
            SSLServerSocketFactory.defaultName = Security.getProperty("ssl.ServerSocketFactory.provider");
            if (SSLServerSocketFactory.defaultName != null) {
                ClassLoader cl = Thread.currentThread().getContextClassLoader();
                if (cl == null) {
                    cl = ClassLoader.getSystemClassLoader();
                }
                try {
                    SSLServerSocketFactory.defaultServerSocketFactory = (ServerSocketFactory) Class.forName(SSLServerSocketFactory.defaultName, true, cl).newInstance();
                } catch (Exception e) {
                }
            }
            return null;
        }
    }

    public abstract String[] getDefaultCipherSuites();

    public abstract String[] getSupportedCipherSuites();

    public static synchronized ServerSocketFactory getDefault() {
        ServerSocketFactory serverSocketFactory;
        synchronized (SSLServerSocketFactory.class) {
            if (defaultServerSocketFactory != null) {
                serverSocketFactory = defaultServerSocketFactory;
            } else {
                if (defaultName == null) {
                    AccessController.doPrivileged(new C00451());
                }
                if (defaultServerSocketFactory == null) {
                    SSLContext context = DefaultSSLContext.getContext();
                    if (context != null) {
                        defaultServerSocketFactory = context.getServerSocketFactory();
                    }
                }
                if (defaultServerSocketFactory == null) {
                    defaultServerSocketFactory = new DefaultSSLServerSocketFactory("No ServerSocketFactory installed");
                }
                serverSocketFactory = defaultServerSocketFactory;
            }
        }
        return serverSocketFactory;
    }

    protected SSLServerSocketFactory() {
    }
}
