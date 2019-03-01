package custom.org.apache.harmony.security.x509;

import java.security.PublicKey;

public class X509PublicKey implements PublicKey {
    private final String algorithm;
    private final byte[] encoded;
    private final byte[] keyBytes;

    public X509PublicKey(String algorithm, byte[] encoded, byte[] keyBytes) {
        this.algorithm = algorithm;
        this.encoded = encoded;
        this.keyBytes = keyBytes;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        return this.encoded;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder("algorithm = ");
        buf.append(this.algorithm);
        buf.append(", params unparsed, unparsed keybits = \n");
        return buf.toString();
    }
}
