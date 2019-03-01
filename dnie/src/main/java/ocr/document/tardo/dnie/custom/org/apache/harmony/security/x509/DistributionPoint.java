package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;

public class DistributionPoint {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Explicit(0, DistributionPointName.ASN1), new ASN1Implicit(1, ReasonFlags.ASN1), new ASN1Implicit(2, GeneralNames.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            return new DistributionPoint((DistributionPointName) values[0], (ReasonFlags) values[1], (GeneralNames) values[2]);
        }

        protected void getValues(Object object, Object[] values) {
            DistributionPoint dp = (DistributionPoint) object;
            values[0] = dp.distributionPoint;
            values[1] = dp.reasons;
            values[2] = dp.cRLIssuer;
        }
    };
    private final GeneralNames cRLIssuer;
    private final DistributionPointName distributionPoint;
    private final ReasonFlags reasons;

    public DistributionPoint() {
        this.distributionPoint = null;
        this.reasons = null;
        this.cRLIssuer = null;
    }

    public DistributionPoint(DistributionPointName distributionPoint, ReasonFlags reasons, GeneralNames cRLIssuer) {
        if (reasons != null && distributionPoint == null && cRLIssuer == null) {
            throw new IllegalArgumentException(Messages.getString("security.17F"));
        }
        this.distributionPoint = distributionPoint;
        this.reasons = reasons;
        this.cRLIssuer = cRLIssuer;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix);
        buffer.append("Distribution Point: [\n");
        if (this.distributionPoint != null) {
            this.distributionPoint.dumpValue(buffer, prefix + "  ");
        }
        if (this.reasons != null) {
            this.reasons.dumpValue(buffer, prefix + "  ");
        }
        if (this.cRLIssuer != null) {
            buffer.append(prefix);
            buffer.append("  CRL Issuer: [\n");
            this.cRLIssuer.dumpValue(buffer, prefix + "    ");
            buffer.append(prefix);
            buffer.append("  ]\n");
        }
        buffer.append(prefix);
        buffer.append("]\n");
    }
}
