package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Boolean;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class BasicConstraints extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Boolean.getInstance(), ASN1Integer.getInstance()}) {
        public Object getDecodedObject(BerInputStream in) throws IOException {
            return in.content;
        }

        protected void getValues(Object object, Object[] values) {
            Object[] vals = (Object[]) object;
            values[0] = (Boolean) vals[0];
            values[1] = ((BigInteger) vals[1]).toByteArray();
        }
    };
    private boolean cA = false;
    private int pathLenConstraint = Integer.MAX_VALUE;

    public BasicConstraints(boolean cA, int pathLenConstraint) {
        this.cA = cA;
        this.pathLenConstraint = pathLenConstraint;
    }

    public BasicConstraints(byte[] encoding) throws IOException {
        super(encoding);
        Object[] values = (Object[]) ASN1.decode(encoding);
        this.cA = ((Boolean) values[0]).booleanValue();
        if (values[1] != null) {
            this.pathLenConstraint = new BigInteger((byte[]) values[1]).intValue();
        }
    }

    public boolean getCA() {
        return this.cA;
    }

    public int getPathLenConstraint() {
        return this.pathLenConstraint;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(new Object[]{Boolean.valueOf(this.cA), BigInteger.valueOf((long) this.pathLenConstraint)});
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("BasicConstraints [\n").append(prefix).append("  CA: ").append(this.cA).append("\n  ").append(prefix).append("pathLenConstraint: ").append(this.pathLenConstraint).append('\n').append(prefix).append("]\n");
    }
}
