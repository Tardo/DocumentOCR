package es.inteco.labs.net;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.entropy.decoder.EntropyDecoder;

public final class HashedCertificatesOnlyTrustManager implements X509TrustManager {
    private static final char[] HEX_CHARS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', BitstreamReaderAgent.OPT_PREFIX, EntropyDecoder.OPT_PREFIX, 'D', 'E', 'F'};
    private Set<String> trustedFingerprints;
    private X509TrustManager x509TrustManager;

    public HashedCertificatesOnlyTrustManager(KeyStore trustStore, Set<String> trustedCertificateFingerprints) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        for (int i = 0; i < trustManagers.length; i++) {
            if (trustManagers[i] instanceof X509TrustManager) {
                this.x509TrustManager = (X509TrustManager) trustManagers[i];
                this.trustedFingerprints = trustedCertificateFingerprints;
                return;
            }
        }
        throw new NoSuchAlgorithmException("Couldn't initialize");
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(chain, authType);
        int i = 0;
        while (i < chain.length) {
            String fingerPrint = "";
            try {
                fingerPrint = getFingerPrint(chain[i]);
            } catch (NoSuchAlgorithmException e) {
                NetLogger.m7w("Unable to calculate SHA1 fingerprint for " + chain[i].getSubjectDN());
            }
            if (!this.trustedFingerprints.contains(fingerPrint)) {
                i++;
            } else {
                return;
            }
        }
        throw new CertificateException("Server certificate not allowed");
    }

    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }

    public static String getFingerPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert.getEncoded());
        return hexify(md.digest(), false);
    }

    private static String hexify(byte[] abyte, boolean separator) {
        if (abyte == null) {
            return "null";
        }
        StringBuffer stringbuffer = new StringBuffer(256);
        int i = 0;
        for (int j = 0; j < abyte.length; j++) {
            if (separator && i > 0) {
                stringbuffer.append('-');
            }
            stringbuffer.append(HEX_CHARS[(abyte[j] >> 4) & 15]);
            stringbuffer.append(HEX_CHARS[abyte[j] & 15]);
            i++;
            if (i == 16) {
                if (separator) {
                    stringbuffer.append('\n');
                }
                i = 0;
            }
        }
        return stringbuffer.toString();
    }
}
