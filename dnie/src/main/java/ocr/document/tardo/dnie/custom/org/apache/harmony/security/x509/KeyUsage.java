package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString.ASN1NamedBitList;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import java.io.IOException;

public class KeyUsage extends ExtensionValue {
    private static final ASN1Type ASN1 = new ASN1NamedBitList(9);
    private static final String[] USAGES = new String[]{"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};
    private final boolean[] keyUsage;

    public KeyUsage(boolean[] keyUsage) {
        this.keyUsage = keyUsage;
    }

    public KeyUsage(byte[] encoding) throws IOException {
        super(encoding);
        this.keyUsage = (boolean[]) ASN1.decode(encoding);
    }

    public boolean[] getKeyUsage() {
        return this.keyUsage;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this.keyUsage);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("KeyUsage [\n");
        for (int i = 0; i < this.keyUsage.length; i++) {
            if (this.keyUsage[i]) {
                buffer.append(prefix).append("  ").append(USAGES[i]).append('\n');
            }
        }
        buffer.append(prefix).append("]\n");
    }
}
