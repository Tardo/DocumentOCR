package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CertResponse extends ASN1Encodable {
    private DERInteger certReqId;
    private CertifiedKeyPair certifiedKeyPair;
    private ASN1OctetString rspInfo;
    private PKIStatusInfo status;

    private CertResponse(ASN1Sequence seq) {
        this.certReqId = DERInteger.getInstance(seq.getObjectAt(0));
        this.status = PKIStatusInfo.getInstance(seq.getObjectAt(1));
        if (seq.size() < 3) {
            return;
        }
        if (seq.size() == 3) {
            DEREncodable o = seq.getObjectAt(2);
            if (o instanceof ASN1OctetString) {
                this.rspInfo = ASN1OctetString.getInstance(o);
                return;
            } else {
                this.certifiedKeyPair = CertifiedKeyPair.getInstance(o);
                return;
            }
        }
        this.certifiedKeyPair = CertifiedKeyPair.getInstance(seq.getObjectAt(2));
        this.rspInfo = ASN1OctetString.getInstance(seq.getObjectAt(3));
    }

    public static CertResponse getInstance(Object o) {
        if (o instanceof CertResponse) {
            return (CertResponse) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertResponse((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertResponse(DERInteger certReqId, PKIStatusInfo status) {
        this(certReqId, status, null, null);
    }

    public CertResponse(DERInteger certReqId, PKIStatusInfo status, CertifiedKeyPair certifiedKeyPair, ASN1OctetString rspInfo) {
        if (certReqId == null) {
            throw new IllegalArgumentException("'certReqId' cannot be null");
        } else if (status == null) {
            throw new IllegalArgumentException("'status' cannot be null");
        } else {
            this.certReqId = certReqId;
            this.status = status;
            this.certifiedKeyPair = certifiedKeyPair;
            this.rspInfo = rspInfo;
        }
    }

    public DERInteger getCertReqId() {
        return this.certReqId;
    }

    public PKIStatusInfo getStatus() {
        return this.status;
    }

    public CertifiedKeyPair getCertifiedKeyPair() {
        return this.certifiedKeyPair;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certReqId);
        v.add(this.status);
        if (this.certifiedKeyPair != null) {
            v.add(this.certifiedKeyPair);
        }
        if (this.rspInfo != null) {
            v.add(this.rspInfo);
        }
        return new DERSequence(v);
    }
}
