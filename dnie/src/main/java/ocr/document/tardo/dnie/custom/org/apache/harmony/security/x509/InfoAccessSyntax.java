package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class InfoAccessSyntax extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(AccessDescription.ASN1) {
        public Object getDecodedObject(BerInputStream in) throws IOException {
            return new InfoAccessSyntax((List) in.content, in.getEncoded());
        }

        public Collection getValues(Object object) {
            return ((InfoAccessSyntax) object).accessDescriptions;
        }
    };
    private final List accessDescriptions;

    public InfoAccessSyntax(List accessDescriptions) throws IOException {
        this(accessDescriptions, null);
    }

    private InfoAccessSyntax(List accessDescriptions, byte[] encoding) throws IOException {
        if (accessDescriptions == null || accessDescriptions.isEmpty()) {
            throw new IOException(Messages.getString("security.1A3"));
        }
        this.accessDescriptions = accessDescriptions;
        this.encoding = encoding;
    }

    public List getAccessDescriptions() {
        return new ArrayList(this.accessDescriptions);
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public static InfoAccessSyntax decode(byte[] encoding) throws IOException {
        return (InfoAccessSyntax) ASN1.decode(encoding);
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("\n---- InfoAccessSyntax:");
        if (this.accessDescriptions != null) {
            for (Object append : this.accessDescriptions) {
                res.append('\n');
                res.append(append);
            }
        }
        res.append("\n---- InfoAccessSyntax END\n");
        return res.toString();
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("AccessDescriptions:\n");
        if (this.accessDescriptions == null || this.accessDescriptions.isEmpty()) {
            buffer.append("NULL\n");
            return;
        }
        for (Object obj : this.accessDescriptions) {
            buffer.append(obj.toString());
        }
    }
}
