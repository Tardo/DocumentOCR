package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class POPODecKeyRespContent extends ASN1Encodable {
    private ASN1Sequence content;

    private POPODecKeyRespContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static POPODecKeyRespContent getInstance(Object o) {
        if (o instanceof POPODecKeyRespContent) {
            return (POPODecKeyRespContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new POPODecKeyRespContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERInteger[] toDERIntegerArray() {
        DERInteger[] result = new DERInteger[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = DERInteger.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}