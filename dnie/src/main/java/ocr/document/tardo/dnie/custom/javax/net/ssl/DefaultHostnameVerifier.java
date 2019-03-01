package custom.javax.net.ssl;

class DefaultHostnameVerifier implements HostnameVerifier {
    DefaultHostnameVerifier() {
    }

    public boolean verify(String hostname, SSLSession session) {
        return false;
    }
}
