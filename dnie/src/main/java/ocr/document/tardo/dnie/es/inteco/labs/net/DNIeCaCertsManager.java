package es.inteco.labs.net;

public final class DNIeCaCertsManager {
    private static CaCertificatesHandler caCertHandler = null;

    public static CaCertificatesHandler getCaCertHandler() {
        return caCertHandler;
    }

    public static void setCaCertHandler(CaCertificatesHandler caCertificatesHandler) {
        caCertHandler = caCertificatesHandler;
    }

    private DNIeCaCertsManager() {
    }
}
