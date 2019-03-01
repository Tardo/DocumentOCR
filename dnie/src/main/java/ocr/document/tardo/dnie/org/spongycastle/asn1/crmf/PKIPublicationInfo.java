package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class PKIPublicationInfo extends ASN1Encodable {
    private DERInteger action;
    private ASN1Sequence pubInfos;

    private PKIPublicationInfo(ASN1Sequence seq) {
        this.action = DERInteger.getInstance(seq.getObjectAt(0));
        this.pubInfos = ASN1Sequence.getInstance(seq.getObjectAt(1));
    }

    public static PKIPublicationInfo getInstance(Object o) {
        if (o instanceof PKIPublicationInfo) {
            return (PKIPublicationInfo) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PKIPublicationInfo((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERInteger getAction() {
        return this.action;
    }

    public SinglePubInfo[] getPubInfos() {
        if (this.pubInfos == null) {
            return null;
        }
        SinglePubInfo[] results = new SinglePubInfo[this.pubInfos.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = SinglePubInfo.getInstance(this.pubInfos.getObjectAt(i));
        }
        return results;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.action);
        v.add(this.pubInfos);
        return new DERSequence(v);
    }
}
