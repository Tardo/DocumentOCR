package custom.org.apache.harmony.security.x509;

import java.io.IOException;
import java.util.List;

public class AlternativeName extends ExtensionValue {
    public static final boolean ISSUER = false;
    public static final boolean SUBJECT = true;
    private GeneralNames alternativeNames;
    private boolean which;

    public AlternativeName(boolean which, GeneralNames alternativeNames) {
        this.which = which;
        this.alternativeNames = alternativeNames;
    }

    public AlternativeName(boolean which, byte[] encoding) throws IOException {
        super(encoding);
        this.which = which;
        this.alternativeNames = (GeneralNames) GeneralNames.ASN1.decode(encoding);
    }

    public List getAlternativeNames() {
        return this.alternativeNames.getPairsList();
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = GeneralNames.ASN1.encode(this.alternativeNames);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append(this.which ? "Subject" : "Issuer").append(" Alternative Names [\n");
        this.alternativeNames.dumpValue(buffer, prefix + "  ");
        buffer.append(prefix).append("]\n");
    }
}
