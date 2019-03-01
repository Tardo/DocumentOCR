package custom.org.apache.harmony.security.asn1;

public abstract class ASN1Primitive extends ASN1Type {
    public ASN1Primitive(int tagNumber) {
        super(tagNumber);
    }

    public final boolean checkTag(int identifier) {
        return this.id == identifier;
    }

    public void encodeASN(BerOutputStream out) {
        out.encodeTag(this.id);
        encodeContent(out);
    }
}
