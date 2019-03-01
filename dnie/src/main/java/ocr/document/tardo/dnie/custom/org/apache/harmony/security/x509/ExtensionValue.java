package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.utils.Array;

public class ExtensionValue {
    protected byte[] encoding;

    public ExtensionValue(byte[] encoding) {
        this.encoding = encoding;
    }

    public byte[] getEncoded() {
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Unparseable extension value:\n");
        if (this.encoding == null) {
            this.encoding = getEncoded();
        }
        if (this.encoding == null) {
            buffer.append("NULL\n");
        } else {
            buffer.append(Array.toString(this.encoding, prefix));
        }
    }

    public void dumpValue(StringBuffer buffer) {
        dumpValue(buffer, "");
    }
}
