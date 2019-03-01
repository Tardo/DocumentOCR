package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.utils.Array;
import java.io.IOException;

public class SubjectKeyIdentifier extends ExtensionValue {
    private final byte[] keyIdentifier;

    public SubjectKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public static SubjectKeyIdentifier decode(byte[] encoding) throws IOException {
        SubjectKeyIdentifier res = new SubjectKeyIdentifier((byte[]) ASN1OctetString.getInstance().decode(encoding));
        res.encoding = encoding;
        return res;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1OctetString.getInstance().encode(this.keyIdentifier);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("SubjectKeyIdentifier: [\n");
        buffer.append(Array.toString(this.keyIdentifier, prefix));
        buffer.append(prefix).append("]\n");
    }
}
