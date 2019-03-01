package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Integer;
import java.io.IOException;
import java.math.BigInteger;

public class InhibitAnyPolicy extends ExtensionValue {
    private int skipCerts;

    public InhibitAnyPolicy(int skipCerts) {
        this.skipCerts = skipCerts;
    }

    public InhibitAnyPolicy(byte[] encoding) throws IOException {
        super(encoding);
        this.skipCerts = new BigInteger((byte[]) ASN1Integer.getInstance().decode(encoding)).intValue();
    }

    public int getSkipCerts() {
        return this.skipCerts;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1Integer.getInstance().encode(ASN1Integer.fromIntValue(this.skipCerts));
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Inhibit Any-Policy: ").append(this.skipCerts).append('\n');
    }
}
