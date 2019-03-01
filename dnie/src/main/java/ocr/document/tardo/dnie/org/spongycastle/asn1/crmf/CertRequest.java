package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CertRequest extends ASN1Encodable {
    private DERInteger certReqId;
    private CertTemplate certTemplate;
    private Controls controls;

    private CertRequest(ASN1Sequence seq) {
        this.certReqId = DERInteger.getInstance(seq.getObjectAt(0));
        this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.controls = Controls.getInstance(seq.getObjectAt(2));
        }
    }

    public static CertRequest getInstance(Object o) {
        if (o instanceof CertRequest) {
            return (CertRequest) o;
        }
        if (o != null) {
            return new CertRequest(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CertRequest(int certReqId, CertTemplate certTemplate, Controls controls) {
        this(new DERInteger(certReqId), certTemplate, controls);
    }

    public CertRequest(DERInteger certReqId, CertTemplate certTemplate, Controls controls) {
        this.certReqId = certReqId;
        this.certTemplate = certTemplate;
        this.controls = controls;
    }

    public DERInteger getCertReqId() {
        return this.certReqId;
    }

    public CertTemplate getCertTemplate() {
        return this.certTemplate;
    }

    public Controls getControls() {
        return this.controls;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certReqId);
        v.add(this.certTemplate);
        if (this.controls != null) {
            v.add(this.controls);
        }
        return new DERSequence(v);
    }
}
