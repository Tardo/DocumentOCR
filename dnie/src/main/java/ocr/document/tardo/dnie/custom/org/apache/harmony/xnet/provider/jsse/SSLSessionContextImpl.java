package custom.org.apache.harmony.xnet.provider.jsse;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

public class SSLSessionContextImpl implements SSLSessionContext {
    private int cacheSize = 0;
    private final Hashtable<IdKey, SSLSessionImpl> sessions = new Hashtable();
    private long timeout = 0;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl$1 */
    class C00591 implements Enumeration {
        Enumeration<IdKey> keys = SSLSessionContextImpl.this.sessions.keys();

        C00591() {
        }

        public boolean hasMoreElements() {
            return this.keys.hasMoreElements();
        }

        public Object nextElement() {
            return ((IdKey) this.keys.nextElement()).id;
        }
    }

    private class IdKey {
        private byte[] id;

        private IdKey(byte[] id) {
            this.id = id;
        }

        public boolean equals(Object o) {
            if (o instanceof IdKey) {
                return Arrays.equals(this.id, ((IdKey) o).id);
            }
            return false;
        }

        public int hashCode() {
            return Arrays.hashCode(this.id);
        }
    }

    public Enumeration getIds() {
        return new C00591();
    }

    public SSLSession getSession(byte[] sessionId) {
        return (SSLSession) this.sessions.get(new IdKey(sessionId));
    }

    public int getSessionCacheSize() {
        return this.cacheSize;
    }

    public int getSessionTimeout() {
        return (int) (this.timeout / 1000);
    }

    public void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("size < 0");
        }
        this.cacheSize = size;
        if (size > 0 && this.sessions.size() < size) {
            removeOldest(size - this.sessions.size());
        }
    }

    public void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }
        this.timeout = (long) (seconds * 1000);
        Enumeration<IdKey> en = this.sessions.keys();
        while (en.hasMoreElements()) {
            IdKey key = (IdKey) en.nextElement();
            if (!((SSLSessionImpl) this.sessions.get(key)).isValid()) {
                this.sessions.remove(key);
            }
        }
    }

    void putSession(SSLSessionImpl ses) {
        if (this.cacheSize > 0 && this.sessions.size() == this.cacheSize) {
            removeOldest(1);
        }
        ses.context = this;
        this.sessions.put(new IdKey(ses.getId()), ses);
    }

    private void removeOldest(int num) {
    }
}
