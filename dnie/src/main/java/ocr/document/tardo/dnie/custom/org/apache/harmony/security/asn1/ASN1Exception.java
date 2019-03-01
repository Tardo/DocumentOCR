package custom.org.apache.harmony.security.asn1;

import java.io.IOException;

public class ASN1Exception extends IOException {
    private static final long serialVersionUID = -3561981263989123987L;

    public ASN1Exception(String message) {
        super(message);
    }
}
