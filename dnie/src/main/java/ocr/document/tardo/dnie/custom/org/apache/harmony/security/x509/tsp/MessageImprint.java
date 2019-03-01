package custom.org.apache.harmony.security.x509.tsp;

import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x509.AlgorithmIdentifier;

public class MessageImprint {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{AlgorithmIdentifier.ASN1, ASN1OctetString.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new MessageImprint((AlgorithmIdentifier) values[0], (byte[]) values[1]);
        }

        protected void getValues(Object object, Object[] values) {
            MessageImprint mi = (MessageImprint) object;
            values[0] = mi.algId;
            values[1] = mi.hashedMessage;
        }
    };
    private final AlgorithmIdentifier algId;
    private final byte[] hashedMessage;

    public MessageImprint(AlgorithmIdentifier algId, byte[] hashedMessage) {
        this.algId = algId;
        this.hashedMessage = hashedMessage;
    }
}
