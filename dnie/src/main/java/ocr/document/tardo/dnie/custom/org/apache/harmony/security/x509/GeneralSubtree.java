package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;

public class GeneralSubtree {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{GeneralName.ASN1, new ASN1Implicit(0, ASN1Integer.getInstance()), new ASN1Implicit(1, ASN1Integer.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            int maximum = -1;
            if (values[2] != null) {
                maximum = ASN1Integer.toIntValue(values[2]);
            }
            return new GeneralSubtree((GeneralName) values[0], ASN1Integer.toIntValue(values[1]), maximum);
        }

        protected void getValues(Object object, Object[] values) {
            GeneralSubtree gs = (GeneralSubtree) object;
            values[0] = gs.base;
            values[1] = ASN1Integer.fromIntValue(gs.minimum);
            if (gs.maximum > -1) {
                values[2] = ASN1Integer.fromIntValue(gs.maximum);
            }
        }
    };
    private final GeneralName base;
    private byte[] encoding;
    private final int maximum;
    private final int minimum;

    public GeneralSubtree(GeneralName base) {
        this(base, 0, -1);
    }

    public GeneralSubtree(GeneralName base, int minimum) {
        this(base, minimum, -1);
    }

    public GeneralSubtree(GeneralName base, int minimum, int maximum) {
        this.base = base;
        this.minimum = minimum;
        this.maximum = maximum;
    }

    public GeneralName getBase() {
        return this.base;
    }

    public int getMaximum() {
        return this.maximum;
    }

    public int getMinimum() {
        return this.minimum;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("General Subtree: [\n");
        buffer.append(prefix).append("  base: ").append(this.base).append('\n');
        buffer.append(prefix).append("  minimum: ").append(this.minimum).append('\n');
        if (this.maximum >= 0) {
            buffer.append(prefix).append("  maximum: ").append(this.maximum).append('\n');
        }
        buffer.append(prefix).append("]\n");
    }
}
