package es.inteco.labs.net.auth.dnie;

import es.inteco.labs.net.NetLogger;
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
import java.util.Vector;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

public class DNIeKeyManagerImpl extends X509ExtendedKeyManager {
    private KeyStore ks;
    private char[] pass;

    public DNIeKeyManagerImpl(KeyStore keyStore, char[] pwd) {
        this.ks = keyStore;
        if (pwd != null) {
            this.pass = (char[]) pwd.clone();
        } else {
            this.pass = null;
        }
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(keyType, issuers);
        if (al == null) {
            return null;
        }
        for (int i = 0; i < al.length; i++) {
            if (al[i].toLowerCase().contains("autenticacion")) {
                return al[i];
            }
        }
        return al[0];
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String[] al = chooseAlias(new String[]{keyType}, issuers);
        return al == null ? null : al[0];
    }

    public X509Certificate[] getCertificateChain(String alias) {
        try {
            if (this.ks.containsAlias(alias)) {
                Certificate[] certs = this.ks.getCertificateChain(alias);
                if (certs[0] instanceof X509Certificate) {
                    X509Certificate[] x509CertificateArr = new X509Certificate[certs.length];
                    for (int i = 0; i < certs.length; i++) {
                        x509CertificateArr[i] = (X509Certificate) certs[i];
                    }
                    return x509CertificateArr;
                }
            }
        } catch (KeyStoreException e) {
            NetLogger.m4e(e);
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
        try {
            if (this.ks.containsAlias(alias)) {
                return (PrivateKey) this.ks.getKey(alias, this.pass);
            }
        } catch (Exception e) {
            NetLogger.m4e(e);
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
        try {
            Enumeration<String> aliases = this.ks.aliases();
            while (aliases.hasMoreElements()) {
                try {
                    String alias = (String) aliases.nextElement();
                    Certificate[] certs = ((PrivateKeyEntry) this.ks.getEntry(alias, new PasswordProtection(this.pass))).getCertificateChain();
                    String alg = certs[0].getPublicKey().getAlgorithm();
                    for (Object equals : keyType) {
                        if (alg.equals(equals)) {
                            if (issuers == null || issuers.length == 0) {
                                found.add(alias);
                            } else {
                                for (int ii = 0; ii < certs.length; ii++) {
                                    if (certs[ii] instanceof X509Certificate) {
                                        X500Principal issuer = certs[ii].getIssuerX500Principal();
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
                } catch (NoSuchAlgorithmException e) {
                } catch (UnrecoverableEntryException e2) {
                }
            }
            if (!found.isEmpty()) {
                return (String[]) found.toArray(new String[found.size()]);
            }
        } catch (KeyStoreException e3) {
            NetLogger.m4e(e3);
        }
        return null;
    }
}
