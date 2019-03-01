package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class PollRepContent extends ASN1Encodable {
    private DERInteger certReqId;
    private DERInteger checkAfter;
    private PKIFreeText reason;

    private PollRepContent(ASN1Sequence seq) {
        this.certReqId = DERInteger.getInstance(seq.getObjectAt(0));
        this.checkAfter = DERInteger.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.reason = PKIFreeText.getInstance(seq.getObjectAt(2));
        }
    }

    public static PollRepContent getInstance(Object o) {
        if (o instanceof PollRepContent) {
            return (PollRepContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PollRepContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERInteger getCertReqId() {
        return this.certReqId;
    }

    public DERInteger getCheckAfter() {
        return this.checkAfter;
    }

    public PKIFreeText getReason() {
        return this.reason;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certReqId);
        v.add(this.checkAfter);
        if (this.reason != null) {
            v.add(this.reason);
        }
        return new DERSequence(v);
    }
}
