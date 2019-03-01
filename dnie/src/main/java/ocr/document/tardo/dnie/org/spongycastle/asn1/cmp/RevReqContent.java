package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class RevReqContent extends ASN1Encodable {
    private ASN1Sequence content;

    private RevReqContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static RevReqContent getInstance(Object o) {
        if (o instanceof RevReqContent) {
            return (RevReqContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new RevReqContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public RevReqContent(RevDetails revDetails) {
        this.content = new DERSequence((DEREncodable) revDetails);
    }

    public RevReqContent(RevDetails[] revDetailsArray) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != revDetailsArray.length; i++) {
            v.add(revDetailsArray[i]);
        }
        this.content = new DERSequence(v);
    }

    public RevDetails[] toRevDetailsArray() {
        RevDetails[] result = new RevDetails[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = RevDetails.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
