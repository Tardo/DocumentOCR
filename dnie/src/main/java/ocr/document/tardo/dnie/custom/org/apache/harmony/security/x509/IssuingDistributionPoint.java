package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Boolean;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;

public class IssuingDistributionPoint extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Explicit(0, DistributionPointName.ASN1), new ASN1Implicit(1, ASN1Boolean.getInstance()), new ASN1Implicit(2, ASN1Boolean.getInstance()), new ASN1Implicit(3, ReasonFlags.ASN1), new ASN1Implicit(4, ASN1Boolean.getInstance()), new ASN1Implicit(5, ASN1Boolean.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            IssuingDistributionPoint idp = new IssuingDistributionPoint((DistributionPointName) values[0], (ReasonFlags) values[3]);
            idp.encoding = in.getEncoded();
            if (values[1] != null) {
                idp.setOnlyContainsUserCerts(((Boolean) values[1]).booleanValue());
            }
            if (values[2] != null) {
                idp.setOnlyContainsCACerts(((Boolean) values[2]).booleanValue());
            }
            if (values[4] != null) {
                idp.setIndirectCRL(((Boolean) values[4]).booleanValue());
            }
            if (values[5] != null) {
                idp.setOnlyContainsAttributeCerts(((Boolean) values[5]).booleanValue());
            }
            return idp;
        }

        protected void getValues(Object object, Object[] values) {
            Boolean bool;
            Boolean bool2 = null;
            IssuingDistributionPoint idp = (IssuingDistributionPoint) object;
            values[0] = idp.distributionPoint;
            values[1] = idp.onlyContainsUserCerts ? Boolean.TRUE : null;
            if (idp.onlyContainsCACerts) {
                bool = Boolean.TRUE;
            } else {
                bool = null;
            }
            values[2] = bool;
            values[3] = idp.onlySomeReasons;
            if (idp.indirectCRL) {
                bool = Boolean.TRUE;
            } else {
                bool = null;
            }
            values[4] = bool;
            if (idp.onlyContainsAttributeCerts) {
                bool2 = Boolean.TRUE;
            }
            values[5] = bool2;
        }
    };
    private DistributionPointName distributionPoint;
    private boolean indirectCRL = false;
    private boolean onlyContainsAttributeCerts = false;
    private boolean onlyContainsCACerts = false;
    private boolean onlyContainsUserCerts = false;
    private ReasonFlags onlySomeReasons;

    public IssuingDistributionPoint(DistributionPointName distributionPoint, ReasonFlags onlySomeReasons) {
        this.distributionPoint = distributionPoint;
        this.onlySomeReasons = onlySomeReasons;
    }

    public static IssuingDistributionPoint decode(byte[] encoding) throws IOException {
        IssuingDistributionPoint idp = (IssuingDistributionPoint) ASN1.decode(encoding);
        idp.encoding = encoding;
        return idp;
    }

    public void setOnlyContainsUserCerts(boolean onlyContainsUserCerts) {
        this.onlyContainsUserCerts = onlyContainsUserCerts;
    }

    public void setOnlyContainsCACerts(boolean onlyContainsCACerts) {
        this.onlyContainsCACerts = onlyContainsCACerts;
    }

    public void setIndirectCRL(boolean indirectCRL) {
        this.indirectCRL = indirectCRL;
    }

    public void setOnlyContainsAttributeCerts(boolean onlyContainsAttributeCerts) {
        this.onlyContainsAttributeCerts = onlyContainsAttributeCerts;
    }

    public DistributionPointName getDistributionPoint() {
        return this.distributionPoint;
    }

    public boolean getOnlyContainsUserCerts() {
        return this.onlyContainsUserCerts;
    }

    public boolean getOnlyContainsCACerts() {
        return this.onlyContainsCACerts;
    }

    public ReasonFlags getOnlySomeReasons() {
        return this.onlySomeReasons;
    }

    public boolean getIndirectCRL() {
        return this.indirectCRL;
    }

    public boolean getOnlyContainsAttributeCerts() {
        return this.onlyContainsAttributeCerts;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Issuing Distribution Point: [\n");
        if (this.distributionPoint != null) {
            this.distributionPoint.dumpValue(buffer, "  " + prefix);
        }
        buffer.append(prefix).append("  onlyContainsUserCerts: ").append(this.onlyContainsUserCerts).append('\n');
        buffer.append(prefix).append("  onlyContainsCACerts: ").append(this.onlyContainsCACerts).append('\n');
        if (this.onlySomeReasons != null) {
            this.onlySomeReasons.dumpValue(buffer, prefix + "  ");
        }
        buffer.append(prefix).append("  indirectCRL: ").append(this.indirectCRL).append('\n');
        buffer.append(prefix).append("  onlyContainsAttributeCerts: ").append(this.onlyContainsAttributeCerts).append('\n');
    }
}
