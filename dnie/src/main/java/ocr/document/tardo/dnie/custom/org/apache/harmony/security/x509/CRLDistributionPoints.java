package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

public class CRLDistributionPoints extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(DistributionPoint.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new CRLDistributionPoints((List) in.content, in.getEncoded());
        }

        public Collection getValues(Object object) {
            return ((CRLDistributionPoints) object).distributionPoints;
        }
    };
    private List distributionPoints;
    private byte[] encoding;

    public CRLDistributionPoints(List distributionPoints) {
        if (distributionPoints == null || distributionPoints.size() == 0) {
            throw new IllegalArgumentException(Messages.getString("security.17D"));
        }
        this.distributionPoints = distributionPoints;
    }

    public CRLDistributionPoints(List distributionPoints, byte[] encoding) {
        if (distributionPoints == null || distributionPoints.size() == 0) {
            throw new IllegalArgumentException(Messages.getString("security.17D"));
        }
        this.distributionPoints = distributionPoints;
        this.encoding = encoding;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public static CRLDistributionPoints decode(byte[] encoding) throws IOException {
        return (CRLDistributionPoints) ASN1.decode(encoding);
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("CRL Distribution Points: [\n");
        int number = 0;
        for (DistributionPoint dumpValue : this.distributionPoints) {
            number++;
            buffer.append(prefix).append("  [").append(number).append("]\n");
            dumpValue.dumpValue(buffer, prefix + "  ");
        }
        buffer.append(prefix).append("]\n");
    }
}
