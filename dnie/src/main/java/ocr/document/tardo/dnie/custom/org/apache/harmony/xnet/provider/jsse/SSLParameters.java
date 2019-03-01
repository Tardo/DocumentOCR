package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class SSLParameters {
    private static X509KeyManager defaultKeyManager;
    private static SSLParameters defaultParameters;
    private static SecureRandom defaultSecureRandom;
    private static X509TrustManager defaultTrustManager;
    private SSLSessionContextImpl clientSessionContext;
    private boolean client_mode;
    private boolean enable_session_creation;
    private String[] enabledCipherSuiteNames;
    protected CipherSuite[] enabledCipherSuites;
    private String[] enabledProtocols;
    private X509KeyManager keyManager;
    private boolean need_client_auth;
    private SecureRandom secureRandom;
    private SSLSessionContextImpl serverSessionContext;
    private X509TrustManager trustManager;
    private boolean want_client_auth;

    private SSLParameters() {
        this.enabledCipherSuiteNames = null;
        this.enabledProtocols = ProtocolVersion.supportedProtocols;
        this.client_mode = true;
        this.need_client_auth = false;
        this.want_client_auth = false;
        this.enable_session_creation = true;
        this.enabledCipherSuites = CipherSuite.defaultCipherSuites;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    protected SSLParameters(javax.net.ssl.KeyManager[] r8, javax.net.ssl.TrustManager[] r9, java.security.SecureRandom r10, custom.org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl r11, custom.org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl r12) throws java.security.KeyManagementException {
        /*
        r7 = this;
        r7.<init>();
        r7.serverSessionContext = r12;
        r7.clientSessionContext = r11;
        r2 = 0;
        if (r8 == 0) goto L_0x000d;
    L_0x000a:
        r5 = r8.length;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x0023;
    L_0x000d:
        r5 = defaultKeyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x004a;
    L_0x0011:
        r5 = javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm();	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r3 = javax.net.ssl.KeyManagerFactory.getInstance(r5);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = 0;
        r6 = 0;
        r3.init(r5, r6);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r8 = r3.getKeyManagers();	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r2 = 1;
    L_0x0023:
        r5 = r7.keyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x005f;
    L_0x0027:
        r1 = 0;
    L_0x0028:
        r5 = r8.length;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r1 >= r5) goto L_0x0037;
    L_0x002b:
        r5 = r8[r1];	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = r5 instanceof javax.net.ssl.X509KeyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 == 0) goto L_0x0056;
    L_0x0031:
        r5 = r8[r1];	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = (javax.net.ssl.X509KeyManager) r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r7.keyManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x0037:
        r5 = r7.keyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x0059;
    L_0x003b:
        r5 = new java.security.KeyManagementException;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r6 = "No X509KeyManager found";
        r5.<init>(r6);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        throw r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x0043:
        r0 = move-exception;
        r5 = new java.security.KeyManagementException;
        r5.<init>(r0);
        throw r5;
    L_0x004a:
        r5 = defaultKeyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r7.keyManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        goto L_0x0023;
    L_0x004f:
        r0 = move-exception;
        r5 = new java.security.KeyManagementException;
        r5.<init>(r0);
        throw r5;
    L_0x0056:
        r1 = r1 + 1;
        goto L_0x0028;
    L_0x0059:
        if (r2 == 0) goto L_0x005f;
    L_0x005b:
        r5 = r7.keyManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        defaultKeyManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x005f:
        r2 = 0;
        if (r9 == 0) goto L_0x0065;
    L_0x0062:
        r5 = r9.length;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x007c;
    L_0x0065:
        r5 = defaultTrustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x00a3;
    L_0x0069:
        r5 = javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm();	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r4 = javax.net.ssl.TrustManagerFactory.getInstance(r5);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = 0;
        r5 = (java.security.KeyStore) r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r4.init(r5);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r9 = r4.getTrustManagers();	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r2 = 1;
    L_0x007c:
        r5 = r7.trustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x00b1;
    L_0x0080:
        r1 = 0;
    L_0x0081:
        r5 = r9.length;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r1 >= r5) goto L_0x0090;
    L_0x0084:
        r5 = r9[r1];	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = r5 instanceof javax.net.ssl.X509TrustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 == 0) goto L_0x00a8;
    L_0x008a:
        r5 = r9[r1];	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r5 = (javax.net.ssl.X509TrustManager) r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r7.trustManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x0090:
        r5 = r7.trustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        if (r5 != 0) goto L_0x00ab;
    L_0x0094:
        r5 = new java.security.KeyManagementException;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r6 = "No X509TrustManager found";
        r5.<init>(r6);	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        throw r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x009c:
        r0 = move-exception;
        r5 = new java.security.KeyManagementException;
        r5.<init>(r0);
        throw r5;
    L_0x00a3:
        r5 = defaultTrustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        r7.trustManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        goto L_0x007c;
    L_0x00a8:
        r1 = r1 + 1;
        goto L_0x0081;
    L_0x00ab:
        if (r2 == 0) goto L_0x00b1;
    L_0x00ad:
        r5 = r7.trustManager;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
        defaultTrustManager = r5;	 Catch:{ NoSuchAlgorithmException -> 0x0043, KeyStoreException -> 0x004f, UnrecoverableKeyException -> 0x009c }
    L_0x00b1:
        if (r10 != 0) goto L_0x00c3;
    L_0x00b3:
        r5 = defaultSecureRandom;
        if (r5 != 0) goto L_0x00be;
    L_0x00b7:
        r5 = new java.security.SecureRandom;
        r5.<init>();
        defaultSecureRandom = r5;
    L_0x00be:
        r5 = defaultSecureRandom;
        r7.secureRandom = r5;
    L_0x00c2:
        return;
    L_0x00c3:
        r7.secureRandom = r10;
        goto L_0x00c2;
        */
        throw new UnsupportedOperationException("Method not decompiled: custom.org.apache.harmony.xnet.provider.jsse.SSLParameters.<init>(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom, custom.org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl, custom.org.apache.harmony.xnet.provider.jsse.SSLSessionContextImpl):void");
    }

    protected static SSLParameters getDefault() throws KeyManagementException {
        if (defaultParameters == null) {
            defaultParameters = new SSLParameters(null, null, null, new SSLSessionContextImpl(), new SSLSessionContextImpl());
        }
        return (SSLParameters) defaultParameters.clone();
    }

    protected SSLSessionContextImpl getServerSessionContext() {
        return this.serverSessionContext;
    }

    protected SSLSessionContextImpl getClientSessionContext() {
        return this.clientSessionContext;
    }

    protected X509KeyManager getKeyManager() {
        return this.keyManager;
    }

    protected X509TrustManager getTrustManager() {
        return this.trustManager;
    }

    protected SecureRandom getSecureRandom() {
        return this.secureRandom;
    }

    protected String[] getEnabledCipherSuites() {
        if (this.enabledCipherSuiteNames == null) {
            this.enabledCipherSuiteNames = new String[this.enabledCipherSuites.length];
            for (int i = 0; i < this.enabledCipherSuites.length; i++) {
                this.enabledCipherSuiteNames[i] = this.enabledCipherSuites[i].getName();
            }
        }
        return (String[]) this.enabledCipherSuiteNames.clone();
    }

    protected void setEnabledCipherSuites(String[] suites) {
        if (suites == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }
        CipherSuite[] cipherSuites = new CipherSuite[suites.length];
        int i = 0;
        while (i < suites.length) {
            cipherSuites[i] = CipherSuite.getByName(suites[i]);
            if (cipherSuites[i] == null || !cipherSuites[i].supported) {
                throw new IllegalArgumentException(suites[i] + " is not supported.");
            }
            i++;
        }
        this.enabledCipherSuites = cipherSuites;
        this.enabledCipherSuiteNames = suites;
    }

    protected String[] getEnabledProtocols() {
        return (String[]) this.enabledProtocols.clone();
    }

    protected void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("Provided parameter is null");
        }
        int i = 0;
        while (i < protocols.length) {
            if (ProtocolVersion.isSupported(protocols[i])) {
                i++;
            } else {
                throw new IllegalArgumentException("Protocol " + protocols[i] + " is not supported.");
            }
        }
        this.enabledProtocols = protocols;
    }

    protected void setUseClientMode(boolean mode) {
        this.client_mode = mode;
    }

    protected boolean getUseClientMode() {
        return this.client_mode;
    }

    protected void setNeedClientAuth(boolean need) {
        this.need_client_auth = need;
        this.want_client_auth = false;
    }

    protected boolean getNeedClientAuth() {
        return this.need_client_auth;
    }

    protected void setWantClientAuth(boolean want) {
        this.want_client_auth = want;
        this.need_client_auth = false;
    }

    protected boolean getWantClientAuth() {
        return this.want_client_auth;
    }

    protected void setEnableSessionCreation(boolean flag) {
        this.enable_session_creation = flag;
    }

    protected boolean getEnableSessionCreation() {
        return this.enable_session_creation;
    }

    protected Object clone() {
        SSLParameters parameters = new SSLParameters();
        parameters.clientSessionContext = this.clientSessionContext;
        parameters.serverSessionContext = this.serverSessionContext;
        parameters.keyManager = this.keyManager;
        parameters.trustManager = this.trustManager;
        parameters.secureRandom = this.secureRandom;
        parameters.enabledCipherSuites = this.enabledCipherSuites;
        parameters.enabledProtocols = this.enabledProtocols;
        parameters.client_mode = this.client_mode;
        parameters.need_client_auth = this.need_client_auth;
        parameters.want_client_auth = this.want_client_auth;
        parameters.enable_session_creation = this.enable_session_creation;
        return parameters;
    }
}
