package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Choice;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.Name;
import java.io.IOException;

public class DistributionPointName {
    public static final ASN1Choice ASN1 = new ASN1Choice(new ASN1Type[]{new ASN1Implicit(0, GeneralNames.ASN1), new ASN1Implicit(1, Name.ASN1_RDN)}) {
        public int getIndex(Object object) {
            return ((DistributionPointName) object).fullName == null ? 1 : 0;
        }

        protected Object getDecodedObject(BerInputStream in) throws IOException {
            if (in.choiceIndex == 0) {
                return new DistributionPointName((GeneralNames) in.content);
            }
            return new DistributionPointName((Name) in.content);
        }

        public Object getObjectToEncode(Object object) {
            DistributionPointName dpn = (DistributionPointName) object;
            if (dpn.fullName == null) {
                return dpn.nameRelativeToCRLIssuer;
            }
            return dpn.fullName;
        }
    };
    private final GeneralNames fullName;
    private final Name nameRelativeToCRLIssuer;

    public DistributionPointName(GeneralNames fullName) {
        this.fullName = fullName;
        this.nameRelativeToCRLIssuer = null;
    }

    public DistributionPointName(Name nameRelativeToCRLIssuer) {
        this.fullName = null;
        this.nameRelativeToCRLIssuer = nameRelativeToCRLIssuer;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix);
        buffer.append("Distribution Point Name: [\n");
        if (this.fullName != null) {
            this.fullName.dumpValue(buffer, prefix + "  ");
        } else {
            buffer.append(prefix);
            buffer.append("  ");
            buffer.append(this.nameRelativeToCRLIssuer.getName("RFC2253"));
        }
        buffer.append(prefix);
        buffer.append("]\n");
    }
}
