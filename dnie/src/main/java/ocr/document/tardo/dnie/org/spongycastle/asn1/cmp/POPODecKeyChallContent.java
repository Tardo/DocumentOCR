package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;

public class POPODecKeyChallContent extends ASN1Encodable {
    private ASN1Sequence content;

    private POPODecKeyChallContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static POPODecKeyChallContent getInstance(Object o) {
        if (o instanceof POPODecKeyChallContent) {
            return (POPODecKeyChallContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new POPODecKeyChallContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public Challenge[] toChallengeArray() {
        Challenge[] result = new Challenge[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = Challenge.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.content;
    }
}
