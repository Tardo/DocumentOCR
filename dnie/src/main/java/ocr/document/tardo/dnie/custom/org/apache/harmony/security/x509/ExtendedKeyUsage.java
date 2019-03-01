package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

public class ExtendedKeyUsage extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(new C02541());
    private List keys;

    /* renamed from: custom.org.apache.harmony.security.x509.ExtendedKeyUsage$1 */
    static class C02541 extends ASN1Oid {
        C02541() {
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            return ObjectIdentifier.toString((int[]) super.getDecodedObject(in));
        }
    }

    public ExtendedKeyUsage(List keys) {
        this.keys = keys;
    }

    public ExtendedKeyUsage(byte[] encoding) {
        super(encoding);
    }

    public List getExtendedKeyUsage() throws IOException {
        if (this.keys == null) {
            this.keys = (List) ASN1.decode(getEncoded());
        }
        return this.keys;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this.keys);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Extended Key Usage: ");
        if (this.keys == null) {
            try {
                this.keys = getExtendedKeyUsage();
            } catch (IOException e) {
                super.dumpValue(buffer);
                return;
            }
        }
        buffer.append('[');
        Iterator it = this.keys.iterator();
        while (it.hasNext()) {
            buffer.append(" \"").append(it.next()).append('\"');
            if (it.hasNext()) {
                buffer.append(',');
            }
        }
        buffer.append(" ]\n");
    }
}
