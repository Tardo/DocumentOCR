package es.inteco.labs.net;

import java.security.KeyStore;
import java.util.HashSet;

public interface CaCertificatesHandler {
    Object getAndroidContext();

    KeyStore getCaKeyStore();

    HashSet<String> getValidCertificates();
}
