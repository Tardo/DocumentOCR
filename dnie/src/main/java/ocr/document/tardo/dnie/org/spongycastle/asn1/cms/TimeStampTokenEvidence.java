package org.spongycastle.asn1.cms;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class TimeStampTokenEvidence extends ASN1Encodable {
    private TimeStampAndCRL[] timeStampAndCRLs;

    public TimeStampTokenEvidence(TimeStampAndCRL[] timeStampAndCRLs) {
        this.timeStampAndCRLs = timeStampAndCRLs;
    }

    public TimeStampTokenEvidence(TimeStampAndCRL timeStampAndCRL) {
        this.timeStampAndCRLs = new TimeStampAndCRL[1];
        this.timeStampAndCRLs[0] = timeStampAndCRL;
    }

    private TimeStampTokenEvidence(ASN1Sequence seq) {
        this.timeStampAndCRLs = new TimeStampAndCRL[seq.size()];
        int count = 0;
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements()) {
            int count2 = count + 1;
            this.timeStampAndCRLs[count] = TimeStampAndCRL.getInstance(en.nextElement());
            count = count2;
        }
    }

    public static TimeStampTokenEvidence getInstance(ASN1TaggedObject tagged, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(tagged, explicit));
    }

    public static TimeStampTokenEvidence getInstance(Object obj) {
        if (obj instanceof TimeStampTokenEvidence) {
            return (TimeStampTokenEvidence) obj;
        }
        if (obj != null) {
            return new TimeStampTokenEvidence(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public TimeStampAndCRL[] toTimeStampAndCRLArray() {
        return this.timeStampAndCRLs;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != this.timeStampAndCRLs.length; i++) {
            v.add(this.timeStampAndCRLs[i]);
        }
        return new DERSequence(v);
    }
}
