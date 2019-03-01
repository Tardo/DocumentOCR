package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.utils.Array;
import java.io.IOException;
import java.math.BigInteger;

public class AuthorityKeyIdentifier extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Implicit(0, ASN1OctetString.getInstance()), new ASN1Implicit(1, GeneralNames.ASN1), new ASN1Implicit(2, ASN1Integer.getInstance())}) {
        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            byte[] enc = (byte[]) values[2];
            BigInteger authorityCertSerialNumber = null;
            if (enc != null) {
                authorityCertSerialNumber = new BigInteger(enc);
            }
            return new AuthorityKeyIdentifier((byte[]) values[0], (GeneralNames) values[1], authorityCertSerialNumber);
        }

        protected void getValues(Object object, Object[] values) {
            AuthorityKeyIdentifier akid = (AuthorityKeyIdentifier) object;
            values[0] = akid.keyIdentifier;
            values[1] = akid.authorityCertIssuer;
            if (akid.authorityCertSerialNumber != null) {
                values[2] = akid.authorityCertSerialNumber.toByteArray();
            }
        }
    };
    private final GeneralNames authorityCertIssuer;
    private final BigInteger authorityCertSerialNumber;
    private final byte[] keyIdentifier;

    public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames authorityCertIssuer, BigInteger authorityCertSerialNumber) {
        this.keyIdentifier = keyIdentifier;
        this.authorityCertIssuer = authorityCertIssuer;
        this.authorityCertSerialNumber = authorityCertSerialNumber;
    }

    public static AuthorityKeyIdentifier decode(byte[] encoding) throws IOException {
        AuthorityKeyIdentifier aki = (AuthorityKeyIdentifier) ASN1.decode(encoding);
        aki.encoding = encoding;
        return aki;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("AuthorityKeyIdentifier [\n");
        if (this.keyIdentifier != null) {
            buffer.append(prefix).append("  keyIdentifier:\n");
            buffer.append(Array.toString(this.keyIdentifier, prefix + "    "));
        }
        if (this.authorityCertIssuer != null) {
            buffer.append(prefix).append("  authorityCertIssuer: [\n");
            this.authorityCertIssuer.dumpValue(buffer, prefix + "    ");
            buffer.append(prefix).append("  ]\n");
        }
        if (this.authorityCertSerialNumber != null) {
            buffer.append(prefix).append("  authorityCertSerialNumber: ").append(this.authorityCertSerialNumber).append('\n');
        }
        buffer.append(prefix).append("]\n");
    }
}
