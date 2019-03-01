package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class PollReqContent extends ASN1Encodable {
    private ASN1Sequence content;

    private PollReqContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static PollReqContent getInstance(Object o) {
        if (o instanceof PollReqContent) {
            return (PollReqContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PollReqContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERInteger[][] getCertReqIds() {
        DERInteger[][] result = new DERInteger[this.content.size()][];
        for (int i = 0; i != result.length; i++) {
            result[i] = seqenceToDERIntegerArray((ASN1Sequence) this.content.getObjectAt(i));
        }
        return result;
    }

    private DERInteger[] seqenceToDERIntegerArray(ASN1Sequence seq) {
        DERInteger[] result = new DERInteger[seq.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = DERInteger.getInstance(seq.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}