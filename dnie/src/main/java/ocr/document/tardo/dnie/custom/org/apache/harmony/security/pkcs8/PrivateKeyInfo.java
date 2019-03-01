package custom.org.apache.harmony.security.pkcs8;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.AttributeTypeAndValue;
import custom.org.apache.harmony.security.x509.AlgorithmIdentifier;
import java.util.List;

public class PrivateKeyInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), AlgorithmIdentifier.ASN1, ASN1OctetString.getInstance(), new ASN1Implicit(0, new ASN1SetOf(AttributeTypeAndValue.ASN1))}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new PrivateKeyInfo(ASN1Integer.toIntValue(values[0]), (AlgorithmIdentifier) values[1], (byte[]) values[2], (List) values[3], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
            values[0] = ASN1Integer.fromIntValue(privateKeyInfo.version);
            values[1] = privateKeyInfo.privateKeyAlgorithm;
            values[2] = privateKeyInfo.privateKey;
            values[3] = privateKeyInfo.attributes;
        }
    };
    private List attributes;
    private byte[] encoding;
    private byte[] privateKey;
    private AlgorithmIdentifier privateKeyAlgorithm;
    private int version;

    public PrivateKeyInfo(int version, AlgorithmIdentifier privateKeyAlgorithm, byte[] privateKey, List attributes) {
        this.version = version;
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.privateKey = privateKey;
        this.attributes = attributes;
    }

    private PrivateKeyInfo(int version, AlgorithmIdentifier privateKeyAlgorithm, byte[] privateKey, List attributes, byte[] encoding) {
        this(version, privateKeyAlgorithm, privateKey, attributes);
        this.encoding = encoding;
    }

    public int getVersion() {
        return this.version;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.privateKeyAlgorithm;
    }

    public List getAttributes() {
        return this.attributes;
    }

    public byte[] getPrivateKey() {
        return this.privateKey;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
