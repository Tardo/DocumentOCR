package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CertificatePolicies extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(PolicyInformation.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new CertificatePolicies((List) in.content, in.getEncoded());
        }

        public Collection getValues(Object object) {
            return ((CertificatePolicies) object).policyInformations;
        }
    };
    private byte[] encoding;
    private List policyInformations;

    public CertificatePolicies(List policyInformations) {
        this.policyInformations = policyInformations;
    }

    public static CertificatePolicies decode(byte[] encoding) throws IOException {
        CertificatePolicies cps = (CertificatePolicies) ASN1.decode(encoding);
        cps.encoding = encoding;
        return cps;
    }

    private CertificatePolicies(List policyInformations, byte[] encoding) {
        this.policyInformations = policyInformations;
        this.encoding = encoding;
    }

    public List getPolicyInformations() {
        return new ArrayList(this.policyInformations);
    }

    public CertificatePolicies addPolicyInformation(PolicyInformation policyInformation) {
        this.encoding = null;
        if (this.policyInformations == null) {
            this.policyInformations = new ArrayList();
        }
        this.policyInformations.add(policyInformation);
        return this;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("CertificatePolicies [\n");
        for (PolicyInformation dumpValue : this.policyInformations) {
            buffer.append(prefix);
            buffer.append("  ");
            dumpValue.dumpValue(buffer);
            buffer.append('\n');
        }
        buffer.append(prefix).append("]\n");
    }
}
