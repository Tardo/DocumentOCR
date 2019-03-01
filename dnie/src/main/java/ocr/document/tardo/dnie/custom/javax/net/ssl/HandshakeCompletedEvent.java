package custom.javax.net.ssl;

import java.io.Serializable;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.EventObject;
import javax.security.cert.X509Certificate;

public class HandshakeCompletedEvent extends EventObject implements Serializable {
    private static final long serialVersionUID = 7914963744257769778L;
    private transient SSLSession session;

    public HandshakeCompletedEvent(SSLSocket sock, SSLSession s) {
        super(sock);
        this.session = s;
    }

    public SSLSession getSession() {
        return this.session;
    }

    public String getCipherSuite() {
        return this.session.getCipherSuite();
    }

    public Certificate[] getLocalCertificates() {
        return this.session.getLocalCertificates();
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return this.session.getPeerCertificates();
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return this.session.getPeerCertificateChain();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return this.session.getPeerPrincipal();
    }

    public Principal getLocalPrincipal() {
        return this.session.getLocalPrincipal();
    }

    public SSLSocket getSocket() {
        return (SSLSocket) this.source;
    }
}
