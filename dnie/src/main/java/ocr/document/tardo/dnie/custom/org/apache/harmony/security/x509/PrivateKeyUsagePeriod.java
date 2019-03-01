package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1GeneralizedTime;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.util.Date;

public class PrivateKeyUsagePeriod {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Implicit(0, ASN1GeneralizedTime.getInstance()), new ASN1Implicit(1, ASN1GeneralizedTime.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new PrivateKeyUsagePeriod((Date) values[0], (Date) values[1], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            PrivateKeyUsagePeriod pkup = (PrivateKeyUsagePeriod) object;
            values[0] = pkup.notBeforeDate;
            values[1] = pkup.notAfterDate;
        }
    };
    private byte[] encoding;
    private final Date notAfterDate;
    private final Date notBeforeDate;

    public PrivateKeyUsagePeriod(Date notBeforeDate, Date notAfterDate) {
        this(notBeforeDate, notAfterDate, null);
    }

    private PrivateKeyUsagePeriod(Date notBeforeDate, Date notAfterDate, byte[] encoding) {
        this.notBeforeDate = notBeforeDate;
        this.notAfterDate = notAfterDate;
        this.encoding = encoding;
    }

    public Date getNotBefore() {
        return this.notBeforeDate;
    }

    public Date getNotAfter() {
        return this.notAfterDate;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
