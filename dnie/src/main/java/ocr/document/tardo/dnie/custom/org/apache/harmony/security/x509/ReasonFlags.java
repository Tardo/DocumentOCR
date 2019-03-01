package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1BitString.ASN1NamedBitList;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BerOutputStream;
import java.io.IOException;

public class ReasonFlags {
    public static final ASN1BitString ASN1 = new ASN1NamedBitList(REASONS.length) {
        public Object getDecodedObject(BerInputStream in) throws IOException {
            return new ReasonFlags((boolean[]) super.getDecodedObject(in));
        }

        public void setEncodingContent(BerOutputStream out) {
            out.content = ((ReasonFlags) out.content).flags;
            super.setEncodingContent(out);
        }
    };
    static final String[] REASONS = new String[]{"unused", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise"};
    private boolean[] flags;

    public ReasonFlags(boolean[] flags) {
        this.flags = flags;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix);
        buffer.append("ReasonFlags [\n");
        for (int i = 0; i < this.flags.length; i++) {
            if (this.flags[i]) {
                buffer.append(prefix).append("  ").append(REASONS[i]).append('\n');
            }
        }
        buffer.append(prefix);
        buffer.append("]\n");
    }
}
