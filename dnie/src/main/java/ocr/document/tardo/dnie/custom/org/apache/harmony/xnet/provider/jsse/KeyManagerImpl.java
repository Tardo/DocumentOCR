package custom.org.apache.harmony.xnet.provider.jsse;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

public class KeyManagerImpl extends X509ExtendedKeyManager {
    private final Hashtable<String, PrivateKeyEntry> hash = new Hashtable();

    public KeyManagerImpl(KeyStore keyStore, char[] pwd) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                try {
                    if (keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
                        this.hash.put(alias, (PrivateKeyEntry) keyStore.getEntry(alias, new PasswordProtection(pwd)));
                    }
                } catch (KeyStoreException e) {
                } catch (UnrecoverableEntryException e2) {
                } catch (NoSuchAlgorithmException e3) {
                }
            }
        } catch (KeyStoreException e4) {
        }
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(keyType, issuers);
        return al == null ? null : al[0];
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(new String[]{keyType}, issuers);
        return al == null ? null : al[0];
    }

    public X509Certificate[] getCertificateChain(String alias) {
        if (this.hash.containsKey(alias)) {
            Certificate[] certs = ((PrivateKeyEntry) this.hash.get(alias)).getCertificateChain();
            if (certs[0] instanceof X509Certificate) {
                X509Certificate[] x509CertificateArr = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    x509CertificateArr[i] = (X509Certificate) certs[i];
                }
                return x509CertificateArr;
            }
        }
        return null;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[]{keyType}, issuers);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return chooseAlias(new String[]{keyType}, issuers);
    }

    public PrivateKey getPrivateKey(String alias) {
        if (this.hash.containsKey(alias)) {
            return ((PrivateKeyEntry) this.hash.get(alias)).getPrivateKey();
        }
        return null;
    }

    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        String[] al = chooseAlias(keyType, issuers);
        return al == null ? null : al[0];
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        String[] al = chooseAlias(new String[]{keyType}, issuers);
        return al == null ? null : al[0];
    }

    private String[] chooseAlias(String[] keyType, Principal[] issuers) {
        if (keyType == null || keyType.length == 0) {
            return null;
        }
        Vector<String> found = new Vector();
        Enumeration<String> aliases = this.hash.keys();
        while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            Certificate[] certs = ((PrivateKeyEntry) this.hash.get(alias)).getCertificateChain();
            String alg = certs[0].getPublicKey().getAlgorithm();
            for (Object equals : keyType) {
                if (alg.equals(equals)) {
                    if (issuers == null || issuers.length == 0) {
                        found.add(alias);
                    } else {
                        for (int ii = 0; ii < certs.length; ii++) {
                            if (certs[ii] instanceof X509Certificate) {
                                X500Principal issuer = ((X509Certificate) certs[ii]).getIssuerX500Principal();
                                for (Object equals2 : issuers) {
                                    if (issuer.equals(equals2)) {
                                        found.add(alias);
                                        break;
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
            }
        }
        return !found.isEmpty() ? (String[]) found.toArray(new String[found.size()]) : null;
    }
}
