package custom.javax.net.ssl;

import custom.javax.net.SocketFactory;
import java.io.IOException;
import java.net.Socket;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

public abstract class SSLSocketFactory extends SocketFactory {
    private static String defaultName;
    private static SocketFactory defaultSocketFactory;

    /* renamed from: custom.javax.net.ssl.SSLSocketFactory$1 */
    static class C00461 implements PrivilegedAction<Void> {
        C00461() {
        }

        public Void run() {
            SSLSocketFactory.defaultName = Security.getProperty("ssl.SocketFactory.provider");
            if (SSLSocketFactory.defaultName != null) {
                ClassLoader cl = Thread.currentThread().getContextClassLoader();
                if (cl == null) {
                    cl = ClassLoader.getSystemClassLoader();
                }
                try {
                    SSLSocketFactory.defaultSocketFactory = (SocketFactory) Class.forName(SSLSocketFactory.defaultName, true, cl).newInstance();
                } catch (Exception e) {
                }
            }
            return null;
        }
    }

    public abstract Socket createSocket(Socket socket, String str, int i, boolean z) throws IOException;

    public abstract String[] getDefaultCipherSuites();

    public abstract String[] getSupportedCipherSuites();

    public static synchronized SocketFactory getDefault() {
        SocketFactory socketFactory;
        synchronized (SSLSocketFactory.class) {
            if (defaultSocketFactory != null) {
                socketFactory = defaultSocketFactory;
            } else {
                if (defaultName == null) {
                    AccessController.doPrivileged(new C00461());
                }
                if (defaultSocketFactory == null) {
                    SSLContext context = DefaultSSLContext.getContext();
                    if (context != null) {
                        defaultSocketFactory = context.getSocketFactory();
                    }
                }
                if (defaultSocketFactory == null) {
                    defaultSocketFactory = new DefaultSSLSocketFactory("No SSLSocketFactory installed");
                }
                socketFactory = defaultSocketFactory;
            }
        }
        return socketFactory;
    }
}
