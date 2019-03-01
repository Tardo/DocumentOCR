package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import java.util.Arrays;

public class AlgorithmIdentifier {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), ASN1Any.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new AlgorithmIdentifier(ObjectIdentifier.toString((int[]) values[0]), (byte[]) values[1]);
        }

        protected void getValues(Object object, Object[] values) {
            AlgorithmIdentifier aID = (AlgorithmIdentifier) object;
            values[0] = ObjectIdentifier.toIntArray(aID.getAlgorithm());
            values[1] = aID.getParameters();
        }
    };
    private String algorithm;
    private String algorithmName;
    private byte[] encoding;
    private byte[] parameters;

    public AlgorithmIdentifier(String algorithm) {
        this(algorithm, null, null);
    }

    public AlgorithmIdentifier(String algorithm, byte[] parameters) {
        this(algorithm, parameters, null);
    }

    private AlgorithmIdentifier(String algorithm, byte[] parameters, byte[] encoding) {
        this.algorithm = algorithm;
        this.parameters = parameters;
        this.encoding = encoding;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getAlgorithmName() {
        if (this.algorithmName == null) {
            this.algorithmName = AlgNameMapper.map2AlgName(this.algorithm);
            if (this.algorithmName == null) {
                this.algorithmName = this.algorithm;
            }
        }
        return this.algorithmName;
    }

    public byte[] getParameters() {
        return this.parameters;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public boolean equals(Object ai) {
        if (!(ai instanceof AlgorithmIdentifier)) {
            return false;
        }
        AlgorithmIdentifier algid = (AlgorithmIdentifier) ai;
        if (!this.algorithm.equals(algid.algorithm)) {
            return false;
        }
        if (this.parameters == null) {
            if (algid.parameters != null) {
                return false;
            }
        } else if (!Arrays.equals(this.parameters, algid.parameters)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (this.parameters != null ? this.parameters.hashCode() : 0) + (this.algorithm.hashCode() * 37);
    }

    public void dumpValue(StringBuffer buffer) {
        buffer.append(getAlgorithmName());
        if (this.parameters == null) {
            buffer.append(", no params, ");
        } else {
            buffer.append(", params unparsed, ");
        }
        buffer.append("OID = ");
        buffer.append(getAlgorithm());
    }
}
