package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class PolicyConstraints extends ExtensionValue {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Implicit(0, ASN1Integer.getInstance()), new ASN1Implicit(1, ASN1Integer.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            BigInteger requireExplicitPolicy = null;
            BigInteger inhibitPolicyMapping = null;
            if (values[0] != null) {
                requireExplicitPolicy = new BigInteger((byte[]) values[0]);
            }
            if (values[1] != null) {
                inhibitPolicyMapping = new BigInteger((byte[]) values[1]);
            }
            return new PolicyConstraints(requireExplicitPolicy, inhibitPolicyMapping, in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            PolicyConstraints pc = (PolicyConstraints) object;
            values[0] = pc.requireExplicitPolicy.toByteArray();
            values[1] = pc.inhibitPolicyMapping.toByteArray();
        }
    };
    private byte[] encoding;
    private final BigInteger inhibitPolicyMapping;
    private final BigInteger requireExplicitPolicy;

    public PolicyConstraints() {
        this(null, null);
    }

    public PolicyConstraints(BigInteger requireExplicitPolicy, BigInteger inhibitPolicyMapping) {
        this.requireExplicitPolicy = requireExplicitPolicy;
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    public PolicyConstraints(int requireExplicitPolicy, int inhibitPolicyMapping) {
        this.requireExplicitPolicy = BigInteger.valueOf((long) requireExplicitPolicy);
        this.inhibitPolicyMapping = BigInteger.valueOf((long) inhibitPolicyMapping);
    }

    public PolicyConstraints(byte[] encoding) throws IOException {
        super(encoding);
        PolicyConstraints pc = (PolicyConstraints) ASN1.decode(encoding);
        this.requireExplicitPolicy = pc.requireExplicitPolicy;
        this.inhibitPolicyMapping = pc.inhibitPolicyMapping;
    }

    private PolicyConstraints(BigInteger requireExplicitPolicy, BigInteger inhibitPolicyMapping, byte[] encoding) {
        this(requireExplicitPolicy, inhibitPolicyMapping);
        this.encoding = encoding;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("PolicyConstraints: [\n");
        if (this.requireExplicitPolicy != null) {
            buffer.append(prefix).append("  requireExplicitPolicy: ").append(this.requireExplicitPolicy).append('\n');
        }
        if (this.inhibitPolicyMapping != null) {
            buffer.append(prefix).append("  inhibitPolicyMapping: ").append(this.inhibitPolicyMapping).append('\n');
        }
        buffer.append(prefix).append("]\n");
    }
}
