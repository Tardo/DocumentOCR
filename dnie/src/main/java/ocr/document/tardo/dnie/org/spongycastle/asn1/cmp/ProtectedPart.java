package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class ProtectedPart extends ASN1Encodable {
    private PKIBody body;
    private PKIHeader header;

    private ProtectedPart(ASN1Sequence seq) {
        this.header = PKIHeader.getInstance(seq.getObjectAt(0));
        this.body = PKIBody.getInstance(seq.getObjectAt(1));
    }

    public static ProtectedPart getInstance(Object o) {
        if (o instanceof ProtectedPart) {
            return (ProtectedPart) o;
        }
        if (o instanceof ASN1Sequence) {
            return new ProtectedPart((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public ProtectedPart(PKIHeader header, PKIBody body) {
        this.header = header;
        this.body = body;
    }

    public PKIHeader getHeader() {
        return this.header;
    }

    public PKIBody getBody() {
        return this.body;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.header);
        v.add(this.body);
        return new DERSequence(v);
    }
}
