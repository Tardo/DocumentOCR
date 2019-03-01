package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class Challenge extends ASN1Encodable {
    private ASN1OctetString challenge;
    private AlgorithmIdentifier owf;
    private ASN1OctetString witness;

    private Challenge(ASN1Sequence seq) {
        int index;
        int index2 = 0;
        if (seq.size() == 3) {
            index = 0 + 1;
            this.owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            index2 = index;
        }
        index = index2 + 1;
        this.witness = ASN1OctetString.getInstance(seq.getObjectAt(index2));
        this.challenge = ASN1OctetString.getInstance(seq.getObjectAt(index));
    }

    public static Challenge getInstance(Object o) {
        if (o instanceof Challenge) {
            return (Challenge) o;
        }
        if (o instanceof ASN1Sequence) {
            return new Challenge((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public AlgorithmIdentifier getOwf() {
        return this.owf;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        addOptional(v, this.owf);
        v.add(this.witness);
        v.add(this.challenge);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }
    }
}
