package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class CommitmentTypeIndication extends ASN1Encodable {
    private DERObjectIdentifier commitmentTypeId;
    private ASN1Sequence commitmentTypeQualifier;

    public CommitmentTypeIndication(ASN1Sequence seq) {
        this.commitmentTypeId = (DERObjectIdentifier) seq.getObjectAt(0);
        if (seq.size() > 1) {
            this.commitmentTypeQualifier = (ASN1Sequence) seq.getObjectAt(1);
        }
    }

    public CommitmentTypeIndication(DERObjectIdentifier commitmentTypeId) {
        this.commitmentTypeId = commitmentTypeId;
    }

    public CommitmentTypeIndication(DERObjectIdentifier commitmentTypeId, ASN1Sequence commitmentTypeQualifier) {
        this.commitmentTypeId = commitmentTypeId;
        this.commitmentTypeQualifier = commitmentTypeQualifier;
    }

    public static CommitmentTypeIndication getInstance(Object obj) {
        if (obj == null || (obj instanceof CommitmentTypeIndication)) {
            return (CommitmentTypeIndication) obj;
        }
        return new CommitmentTypeIndication(ASN1Sequence.getInstance(obj));
    }

    public DERObjectIdentifier getCommitmentTypeId() {
        return this.commitmentTypeId;
    }

    public ASN1Sequence getCommitmentTypeQualifier() {
        return this.commitmentTypeQualifier;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.commitmentTypeId);
        if (this.commitmentTypeQualifier != null) {
            v.add(this.commitmentTypeQualifier);
        }
        return new DERSequence(v);
    }
}
