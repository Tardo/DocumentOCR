package org.spongycastle.asn1.ocsp;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class CrlID extends ASN1Encodable {
    DERInteger crlNum;
    DERGeneralizedTime crlTime;
    DERIA5String crlUrl;

    public CrlID(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = (ASN1TaggedObject) e.nextElement();
            switch (o.getTagNo()) {
                case 0:
                    this.crlUrl = DERIA5String.getInstance(o, true);
                    break;
                case 1:
                    this.crlNum = DERInteger.getInstance(o, true);
                    break;
                case 2:
                    this.crlTime = DERGeneralizedTime.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag number: " + o.getTagNo());
            }
        }
    }

    public DERIA5String getCrlUrl() {
        return this.crlUrl;
    }

    public DERInteger getCrlNum() {
        return this.crlNum;
    }

    public DERGeneralizedTime getCrlTime() {
        return this.crlTime;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.crlUrl != null) {
            v.add(new DERTaggedObject(true, 0, this.crlUrl));
        }
        if (this.crlNum != null) {
            v.add(new DERTaggedObject(true, 1, this.crlNum));
        }
        if (this.crlTime != null) {
            v.add(new DERTaggedObject(true, 2, this.crlTime));
        }
        return new DERSequence(v);
    }
}
