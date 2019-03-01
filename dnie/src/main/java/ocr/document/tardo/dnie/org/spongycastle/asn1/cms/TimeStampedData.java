package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class TimeStampedData extends ASN1Encodable {
    private ASN1OctetString content;
    private DERIA5String dataUri;
    private MetaData metaData;
    private Evidence temporalEvidence;
    private DERInteger version;

    public TimeStampedData(DERIA5String dataUri, MetaData metaData, ASN1OctetString content, Evidence temporalEvidence) {
        this.version = new DERInteger(1);
        this.dataUri = dataUri;
        this.metaData = metaData;
        this.content = content;
        this.temporalEvidence = temporalEvidence;
    }

    private TimeStampedData(ASN1Sequence seq) {
        this.version = DERInteger.getInstance(seq.getObjectAt(0));
        int i = 1;
        if (seq.getObjectAt(1) instanceof DERIA5String) {
            int index = 1 + 1;
            this.dataUri = DERIA5String.getInstance(seq.getObjectAt(1));
            i = index;
        }
        if ((seq.getObjectAt(i) instanceof MetaData) || (seq.getObjectAt(i) instanceof ASN1Sequence)) {
            index = i + 1;
            this.metaData = MetaData.getInstance(seq.getObjectAt(i));
            i = index;
        }
        if (seq.getObjectAt(i) instanceof ASN1OctetString) {
            index = i + 1;
            this.content = ASN1OctetString.getInstance(seq.getObjectAt(i));
            i = index;
        }
        this.temporalEvidence = Evidence.getInstance(seq.getObjectAt(i));
    }

    public static TimeStampedData getInstance(Object obj) {
        if (obj instanceof TimeStampedData) {
            return (TimeStampedData) obj;
        }
        if (obj != null) {
            return new TimeStampedData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DERIA5String getDataUri() {
        return this.dataUri;
    }

    public MetaData getMetaData() {
        return this.metaData;
    }

    public ASN1OctetString getContent() {
        return this.content;
    }

    public Evidence getTemporalEvidence() {
        return this.temporalEvidence;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        if (this.dataUri != null) {
            v.add(this.dataUri);
        }
        if (this.metaData != null) {
            v.add(this.metaData);
        }
        if (this.content != null) {
            v.add(this.content);
        }
        v.add(this.temporalEvidence);
        return new BERSequence(v);
    }
}
