package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class OriginatorInfo extends ASN1Encodable {
    private ASN1Set certs;
    private ASN1Set crls;

    public OriginatorInfo(ASN1Set certs, ASN1Set crls) {
        this.certs = certs;
        this.crls = crls;
    }

    public OriginatorInfo(ASN1Sequence seq) {
        switch (seq.size()) {
            case 0:
                return;
            case 1:
                ASN1TaggedObject o = (ASN1TaggedObject) seq.getObjectAt(0);
                switch (o.getTagNo()) {
                    case 0:
                        this.certs = ASN1Set.getInstance(o, false);
                        return;
                    case 1:
                        this.crls = ASN1Set.getInstance(o, false);
                        return;
                    default:
                        throw new IllegalArgumentException("Bad tag in OriginatorInfo: " + o.getTagNo());
                }
            case 2:
                this.certs = ASN1Set.getInstance((ASN1TaggedObject) seq.getObjectAt(0), false);
                this.crls = ASN1Set.getInstance((ASN1TaggedObject) seq.getObjectAt(1), false);
                return;
            default:
                throw new IllegalArgumentException("OriginatorInfo too big");
        }
    }

    public static OriginatorInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OriginatorInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof OriginatorInfo)) {
            return (OriginatorInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new OriginatorInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid OriginatorInfo: " + obj.getClass().getName());
    }

    public ASN1Set getCertificates() {
        return this.certs;
    }

    public ASN1Set getCRLs() {
        return this.crls;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.certs != null) {
            v.add(new DERTaggedObject(false, 0, this.certs));
        }
        if (this.crls != null) {
            v.add(new DERTaggedObject(false, 1, this.crls));
        }
        return new DERSequence(v);
    }
}
