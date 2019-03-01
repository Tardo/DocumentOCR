package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1GeneralizedTime;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import java.io.IOException;
import java.util.Date;

public class InvalidityDate extends ExtensionValue {
    public static final ASN1Type ASN1 = ASN1GeneralizedTime.getInstance();
    private final Date date;

    public InvalidityDate(Date date) {
        this.date = date;
    }

    public InvalidityDate(byte[] encoding) throws IOException {
        super(encoding);
        this.date = (Date) ASN1.decode(encoding);
    }

    public Date getDate() {
        return this.date;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this.date);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Invalidity Date: [ ").append(this.date).append(" ]\n");
    }
}
