package org.spongycastle.asn1.tsp;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cmp.PKIStatusInfo;
import org.spongycastle.asn1.cms.ContentInfo;

public class TimeStampResp extends ASN1Encodable {
    PKIStatusInfo pkiStatusInfo;
    ContentInfo timeStampToken;

    public static TimeStampResp getInstance(Object o) {
        if (o == null || (o instanceof TimeStampResp)) {
            return (TimeStampResp) o;
        }
        if (o instanceof ASN1Sequence) {
            return new TimeStampResp((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in 'TimeStampResp' factory : " + o.getClass().getName() + ".");
    }

    public TimeStampResp(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.pkiStatusInfo = PKIStatusInfo.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            this.timeStampToken = ContentInfo.getInstance(e.nextElement());
        }
    }

    public TimeStampResp(PKIStatusInfo pkiStatusInfo, ContentInfo timeStampToken) {
        this.pkiStatusInfo = pkiStatusInfo;
        this.timeStampToken = timeStampToken;
    }

    public PKIStatusInfo getStatus() {
        return this.pkiStatusInfo;
    }

    public ContentInfo getTimeStampToken() {
        return this.timeStampToken;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.pkiStatusInfo);
        if (this.timeStampToken != null) {
            v.add(this.timeStampToken);
        }
        return new DERSequence(v);
    }
}
