package custom.javax.net.ssl;

import java.security.cert.CertPathParameters;

public class CertPathTrustManagerParameters implements ManagerFactoryParameters {
    private final CertPathParameters param;

    public CertPathTrustManagerParameters(CertPathParameters parameters) {
        this.param = (CertPathParameters) parameters.clone();
    }

    public CertPathParameters getParameters() {
        return (CertPathParameters) this.param.clone();
    }
}
