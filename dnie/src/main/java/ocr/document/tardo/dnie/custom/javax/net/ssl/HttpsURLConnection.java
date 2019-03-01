package custom.javax.net.ssl;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public abstract class HttpsURLConnection extends HttpURLConnection {
    private static HostnameVerifier defaultHostnameVerifier = new DefaultHostnameVerifier();
    private static SSLSocketFactory defaultSSLSocketFactory = ((SSLSocketFactory) SSLSocketFactory.getDefault());
    protected HostnameVerifier hostnameVerifier = defaultHostnameVerifier;
    private SSLSocketFactory sslSocketFactory = defaultSSLSocketFactory;

    public abstract String getCipherSuite();

    public abstract Certificate[] getLocalCertificates();

    public abstract Certificate[] getServerCertificates() throws SSLPeerUnverifiedException;

    public static void setDefaultHostnameVerifier(HostnameVerifier v) {
        if (v == null) {
            throw new IllegalArgumentException("HostnameVerifier is null");
        }
        defaultHostnameVerifier = v;
    }

    public static HostnameVerifier getDefaultHostnameVerifier() {
        return defaultHostnameVerifier;
    }

    public static void setDefaultSSLSocketFactory(SSLSocketFactory sf) {
        if (sf == null) {
            throw new IllegalArgumentException("SSLSocketFactory is null");
        }
        defaultSSLSocketFactory = sf;
    }

    public static SSLSocketFactory getDefaultSSLSocketFactory() {
        return defaultSSLSocketFactory;
    }

    protected HttpsURLConnection(URL url) {
        super(url);
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        Certificate[] certs = getServerCertificates();
        if (certs != null && certs.length != 0 && (certs[0] instanceof X509Certificate)) {
            return ((X509Certificate) certs[0]).getSubjectX500Principal();
        }
        throw new SSLPeerUnverifiedException("No server's end-entity certificate");
    }

    public Principal getLocalPrincipal() {
        Certificate[] certs = getLocalCertificates();
        if (certs == null || certs.length == 0 || !(certs[0] instanceof X509Certificate)) {
            return null;
        }
        return ((X509Certificate) certs[0]).getSubjectX500Principal();
    }

    public void setHostnameVerifier(HostnameVerifier v) {
        if (v == null) {
            throw new IllegalArgumentException("HostnameVerifier is null");
        }
        this.hostnameVerifier = v;
    }

    public HostnameVerifier getHostnameVerifier() {
        return this.hostnameVerifier;
    }

    public void setSSLSocketFactory(SSLSocketFactory sf) {
        if (sf == null) {
            throw new IllegalArgumentException("SSLSocketFactory is null");
        }
        this.sslSocketFactory = sf;
    }

    public SSLSocketFactory getSSLSocketFactory() {
        return this.sslSocketFactory;
    }
}
