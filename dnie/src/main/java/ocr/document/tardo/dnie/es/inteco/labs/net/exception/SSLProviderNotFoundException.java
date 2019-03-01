package es.inteco.labs.net.exception;

public final class SSLProviderNotFoundException extends RuntimeException {
    private static final long serialVersionUID = -5126437536467627333L;

    public SSLProviderNotFoundException(Exception excp) {
        super(excp);
    }
}
