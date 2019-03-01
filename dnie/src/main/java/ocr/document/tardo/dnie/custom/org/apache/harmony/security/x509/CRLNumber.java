package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import java.io.IOException;
import java.math.BigInteger;

public class CRLNumber extends ExtensionValue {
    public static final ASN1Type ASN1 = ASN1Integer.getInstance();
    private final BigInteger number;

    public CRLNumber(BigInteger number) {
        this.number = number;
    }

    public CRLNumber(byte[] encoding) throws IOException {
        super(encoding);
        this.number = new BigInteger((byte[]) ASN1.decode(encoding));
    }

    public BigInteger getNumber() {
        return this.number;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this.number.toByteArray());
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("CRL Number: [ ").append(this.number).append(" ]\n");
    }
}
