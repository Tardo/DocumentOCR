package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class OtherRecipientInfo extends ASN1Encodable {
    private DERObjectIdentifier oriType;
    private DEREncodable oriValue;

    public OtherRecipientInfo(DERObjectIdentifier oriType, DEREncodable oriValue) {
        this.oriType = oriType;
        this.oriValue = oriValue;
    }

    public OtherRecipientInfo(ASN1Sequence seq) {
        this.oriType = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.oriValue = seq.getObjectAt(1);
    }

    public static OtherRecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OtherRecipientInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof OtherRecipientInfo)) {
            return (OtherRecipientInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new OtherRecipientInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid OtherRecipientInfo: " + obj.getClass().getName());
    }

    public DERObjectIdentifier getType() {
        return this.oriType;
    }

    public DEREncodable getValue() {
        return this.oriValue;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.oriType);
        v.add(this.oriValue);
        return new DERSequence(v);
    }
}
