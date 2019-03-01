package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.DirectoryString;

public class EDIPartyName {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Explicit(0, DirectoryString.ASN1), new ASN1Explicit(1, DirectoryString.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new EDIPartyName((String) values[0], (String) values[1], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            EDIPartyName epn = (EDIPartyName) object;
            values[0] = epn.nameAssigner;
            values[1] = epn.partyName;
        }
    };
    private byte[] encoding;
    private String nameAssigner;
    private String partyName;

    public EDIPartyName(String nameAssigner, String partyName) {
        this.nameAssigner = nameAssigner;
        this.partyName = partyName;
    }

    private EDIPartyName(String nameAssigner, String partyName, byte[] encoding) {
        this.nameAssigner = nameAssigner;
        this.partyName = partyName;
        this.encoding = encoding;
    }

    public String getNameAssigner() {
        return this.nameAssigner;
    }

    public String getPartyName() {
        return this.partyName;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
