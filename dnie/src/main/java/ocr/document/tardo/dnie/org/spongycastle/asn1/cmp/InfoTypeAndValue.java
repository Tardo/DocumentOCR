package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class InfoTypeAndValue extends ASN1Encodable {
    private DERObjectIdentifier infoType;
    private ASN1Encodable infoValue;

    private InfoTypeAndValue(ASN1Sequence seq) {
        this.infoType = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.infoValue = (ASN1Encodable) seq.getObjectAt(1);
        }
    }

    public static InfoTypeAndValue getInstance(Object o) {
        if (o instanceof InfoTypeAndValue) {
            return (InfoTypeAndValue) o;
        }
        if (o instanceof ASN1Sequence) {
            return new InfoTypeAndValue((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public InfoTypeAndValue(DERObjectIdentifier infoType) {
        this.infoType = infoType;
        this.infoValue = null;
    }

    public InfoTypeAndValue(DERObjectIdentifier infoType, ASN1Encodable optionalValue) {
        this.infoType = infoType;
        this.infoValue = optionalValue;
    }

    public DERObjectIdentifier getInfoType() {
        return this.infoType;
    }

    public ASN1Encodable getInfoValue() {
        return this.infoValue;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.infoType);
        if (this.infoValue != null) {
            v.add(this.infoValue);
        }
        return new DERSequence(v);
    }
}
