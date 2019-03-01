package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;

public class SSLSessionImpl implements SSLSession, Cloneable {
    public static final SSLSessionImpl NULL_SESSION = new SSLSessionImpl(null);
    CipherSuite cipherSuite;
    byte[] clientRandom;
    SSLSessionContextImpl context;
    private long creationTime;
    byte[] id;
    final boolean isServer;
    private boolean isValid;
    long lastAccessedTime;
    X509Certificate[] localCertificates;
    byte[] master_secret;
    X509Certificate[] peerCertificates;
    private String peerHost;
    private int peerPort;
    ProtocolVersion protocol;
    byte[] serverRandom;
    private Map<ValueKey, Object> values;

    private static final class ValueKey {
        final AccessControlContext acc = AccessController.getContext();
        final String name;

        ValueKey(String name) {
            this.name = name;
        }

        public int hashCode() {
            int i = 0;
            int hashCode = ((this.acc == null ? 0 : this.acc.hashCode()) + 31) * 31;
            if (this.name != null) {
                i = this.name.hashCode();
            }
            return hashCode + i;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (!(obj instanceof ValueKey)) {
                return false;
            }
            ValueKey other = (ValueKey) obj;
            if (this.acc == null) {
                if (other.acc != null) {
                    return false;
                }
            } else if (!this.acc.equals(other.acc)) {
                return false;
            }
            if (this.name == null) {
                if (other.name != null) {
                    return false;
                }
                return true;
            } else if (this.name.equals(other.name)) {
                return true;
            } else {
                return false;
            }
        }
    }

    public SSLSessionImpl(CipherSuite cipher_suite, SecureRandom sr) {
        this.isValid = true;
        this.values = new HashMap();
        this.peerPort = -1;
        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = this.creationTime;
        if (cipher_suite == null) {
            this.cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
            this.id = new byte[0];
            this.isServer = false;
            return;
        }
        this.cipherSuite = cipher_suite;
        this.id = new byte[32];
        sr.nextBytes(this.id);
        long time = this.creationTime / 1000;
        this.id[28] = (byte) ((int) ((-16777216 & time) >>> 24));
        this.id[29] = (byte) ((int) ((16711680 & time) >>> 16));
        this.id[30] = (byte) ((int) ((65280 & time) >>> 8));
        this.id[31] = (byte) ((int) (255 & time));
        this.isServer = true;
    }

    public SSLSessionImpl(SecureRandom sr) {
        this(null, sr);
    }

    public int getApplicationBufferSize() {
        return 16384;
    }

    public String getCipherSuite() {
        return this.cipherSuite.getName();
    }

    public long getCreationTime() {
        return this.creationTime;
    }

    public byte[] getId() {
        return this.id;
    }

    public long getLastAccessedTime() {
        return this.lastAccessedTime;
    }

    public Certificate[] getLocalCertificates() {
        return this.localCertificates;
    }

    public Principal getLocalPrincipal() {
        if (this.localCertificates == null || this.localCertificates.length <= 0) {
            return null;
        }
        return this.localCertificates[0].getSubjectX500Principal();
    }

    public int getPacketBufferSize() {
        return 18437;
    }

    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (this.peerCertificates == null) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }
        javax.security.cert.X509Certificate[] certs = new javax.security.cert.X509Certificate[this.peerCertificates.length];
        for (int i = 0; i < certs.length; i++) {
            try {
                certs[i] = javax.security.cert.X509Certificate.getInstance(this.peerCertificates[i].getEncoded());
            } catch (CertificateException e) {
            } catch (CertificateEncodingException e2) {
            }
        }
        return certs;
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (this.peerCertificates != null) {
            return this.peerCertificates;
        }
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    public String getPeerHost() {
        return this.peerHost;
    }

    public int getPeerPort() {
        return this.peerPort;
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (this.peerCertificates != null) {
            return this.peerCertificates[0].getSubjectX500Principal();
        }
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    public String getProtocol() {
        return this.protocol.name;
    }

    public SSLSessionContext getSessionContext() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }
        return this.context;
    }

    public Object getValue(String name) {
        if (name != null) {
            return this.values.get(new ValueKey(name));
        }
        throw new IllegalArgumentException("Parameter is null");
    }

    public String[] getValueNames() {
        Vector<String> v = new Vector();
        AccessControlContext currAcc = AccessController.getContext();
        for (ValueKey key : this.values.keySet()) {
            if ((currAcc == null && key.acc == null) || (currAcc != null && currAcc.equals(key.acc))) {
                v.add(key.name);
            }
        }
        return (String[]) v.toArray(new String[v.size()]);
    }

    public void invalidate() {
        this.isValid = false;
    }

    public boolean isValid() {
        if (this.isValid && this.context != null && this.context.getSessionTimeout() != 0 && this.lastAccessedTime + ((long) this.context.getSessionTimeout()) > System.currentTimeMillis()) {
            this.isValid = false;
        }
        return this.isValid;
    }

    public void putValue(String name, Object value) {
        if (name == null || value == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        Object old = this.values.put(new ValueKey(name), value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
        if (old != null && (old instanceof SSLSessionBindingListener)) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    public void removeValue(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Parameter is null");
        }
        this.values.remove(new ValueKey(name));
    }

    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    void setPeer(String peerHost, int peerPort) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }
}
