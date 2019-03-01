package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class CertRepMessage extends ASN1Encodable {
    private ASN1Sequence caPubs;
    private ASN1Sequence response;

    private CertRepMessage(ASN1Sequence seq) {
        int index = 0;
        if (seq.size() > 1) {
            int index2 = 0 + 1;
            this.caPubs = ASN1Sequence.getInstance((ASN1TaggedObject) seq.getObjectAt(0), true);
            index = index2;
        }
        this.response = ASN1Sequence.getInstance(seq.getObjectAt(index));
    }

    public static CertRepMessage getInstance(Object o) {
        if (o instanceof CertRepMessage) {
            return (CertRepMessage) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertRepMessage((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertRepMessage(CMPCertificate[] caPubs, CertResponse[] response) {
        if (response == null) {
            throw new IllegalArgumentException("'response' cannot be null");
        }
        ASN1EncodableVector v;
        if (caPubs != null) {
            v = new ASN1EncodableVector();
            for (DEREncodable add : caPubs) {
                v.add(add);
            }
            this.caPubs = new DERSequence(v);
        }
        v = new ASN1EncodableVector();
        for (DEREncodable add2 : response) {
            v.add(add2);
        }
        this.response = new DERSequence(v);
    }

    public CMPCertificate[] getCaPubs() {
        if (this.caPubs == null) {
            return null;
        }
        CMPCertificate[] results = new CMPCertificate[this.caPubs.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = CMPCertificate.getInstance(this.caPubs.getObjectAt(i));
        }
        return results;
    }

    public CertResponse[] getResponse() {
        CertResponse[] results = new CertResponse[this.response.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = CertResponse.getInstance(this.response.getObjectAt(i));
        }
        return results;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.caPubs != null) {
            v.add(new DERTaggedObject(true, 1, this.caPubs));
        }
        v.add(this.response);
        return new DERSequence(v);
    }
}
