package custom.org.apache.harmony.security.asn1;

public abstract class ASN1Constructured extends ASN1Type {
    public ASN1Constructured(int tagNumber) {
        super(0, tagNumber);
    }

    public ASN1Constructured(int tagClass, int tagNumber) {
        super(tagClass, tagNumber);
    }

    public final boolean checkTag(int identifier) {
        return this.constrId == identifier;
    }

    public void encodeASN(BerOutputStream out) {
        out.encodeTag(this.constrId);
        encodeContent(out);
    }
}
