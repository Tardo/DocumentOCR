package org.spongycastle.asn1.esf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CompleteRevocationRefs extends ASN1Encodable {
    private ASN1Sequence crlOcspRefs;

    public static CompleteRevocationRefs getInstance(Object obj) {
        if (obj instanceof CompleteRevocationRefs) {
            return (CompleteRevocationRefs) obj;
        }
        if (obj != null) {
            return new CompleteRevocationRefs(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("null value in getInstance");
    }

    private CompleteRevocationRefs(ASN1Sequence seq) {
        Enumeration seqEnum = seq.getObjects();
        while (seqEnum.hasMoreElements()) {
            CrlOcspRef.getInstance(seqEnum.nextElement());
        }
        this.crlOcspRefs = seq;
    }

    public CompleteRevocationRefs(CrlOcspRef[] crlOcspRefs) {
        this.crlOcspRefs = new DERSequence((ASN1Encodable[]) crlOcspRefs);
    }

    public CrlOcspRef[] getCrlOcspRefs() {
        CrlOcspRef[] result = new CrlOcspRef[this.crlOcspRefs.size()];
        for (int idx = 0; idx < result.length; idx++) {
            result[idx] = CrlOcspRef.getInstance(this.crlOcspRefs.getObjectAt(idx));
        }
        return result;
    }

    public DERObject toASN1Object() {
        return this.crlOcspRefs;
    }
}