package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.Name;
import java.io.IOException;
import javax.security.auth.x500.X500Principal;

public class CertificateIssuer extends ExtensionValue {
    public static final ASN1Type ASN1 = new ASN1Sequence(new ASN1Type[]{GeneralName.ASN1}) {
        public Object getDecodedObject(BerInputStream in) {
            return ((Name) ((GeneralName) ((Object[]) in.content)[0]).getName()).getX500Principal();
        }

        protected void getValues(Object object, Object[] values) {
            values[0] = object;
        }
    };
    private X500Principal issuer;

    public CertificateIssuer(GeneralName issuer) {
        super(ASN1.encode(issuer));
    }

    public CertificateIssuer(byte[] encoding) {
        super(encoding);
    }

    public X500Principal getIssuer() throws IOException {
        if (this.issuer == null) {
            this.issuer = (X500Principal) ASN1.decode(getEncoded());
        }
        return this.issuer;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Certificate Issuer: ");
        if (this.issuer == null) {
            try {
                this.issuer = getIssuer();
            } catch (IOException e) {
                buffer.append("Unparseable (incorrect!) extension value:\n");
                super.dumpValue(buffer);
            }
        }
        buffer.append(this.issuer).append('\n');
    }
}
