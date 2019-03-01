package org.spongycastle.asn1.crmf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CertReqMsg extends ASN1Encodable {
    private CertRequest certReq;
    private ProofOfPossession popo;
    private ASN1Sequence regInfo;

    private CertReqMsg(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.certReq = CertRequest.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            Object o = en.nextElement();
            if ((o instanceof ASN1TaggedObject) || (o instanceof ProofOfPossession)) {
                this.popo = ProofOfPossession.getInstance(o);
            } else {
                this.regInfo = ASN1Sequence.getInstance(o);
            }
        }
    }

    public static CertReqMsg getInstance(Object o) {
        if (o instanceof CertReqMsg) {
            return (CertReqMsg) o;
        }
        if (o != null) {
            return new CertReqMsg(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CertReqMsg(CertRequest certReq, ProofOfPossession popo, AttributeTypeAndValue[] regInfo) {
        if (certReq == null) {
            throw new IllegalArgumentException("'certReq' cannot be null");
        }
        this.certReq = certReq;
        this.popo = popo;
        if (regInfo != null) {
            this.regInfo = new DERSequence((ASN1Encodable[]) regInfo);
        }
    }

    public CertRequest getCertReq() {
        return this.certReq;
    }

    public ProofOfPossession getPop() {
        return this.popo;
    }

    public ProofOfPossession getPopo() {
        return this.popo;
    }

    public AttributeTypeAndValue[] getRegInfo() {
        if (this.regInfo == null) {
            return null;
        }
        AttributeTypeAndValue[] results = new AttributeTypeAndValue[this.regInfo.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = AttributeTypeAndValue.getInstance(this.regInfo.getObjectAt(i));
        }
        return results;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certReq);
        addOptional(v, this.popo);
        addOptional(v, this.regInfo);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }
    }
}
