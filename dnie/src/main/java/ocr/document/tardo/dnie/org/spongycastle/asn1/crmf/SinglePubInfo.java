package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.GeneralName;

public class SinglePubInfo extends ASN1Encodable {
    private GeneralName pubLocation;
    private DERInteger pubMethod;

    private SinglePubInfo(ASN1Sequence seq) {
        this.pubMethod = DERInteger.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static SinglePubInfo getInstance(Object o) {
        if (o instanceof SinglePubInfo) {
            return (SinglePubInfo) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SinglePubInfo((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public GeneralName getPubLocation() {
        return this.pubLocation;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.pubMethod);
        if (this.pubLocation != null) {
            v.add(this.pubLocation);
        }
        return new DERSequence(v);
    }
}
