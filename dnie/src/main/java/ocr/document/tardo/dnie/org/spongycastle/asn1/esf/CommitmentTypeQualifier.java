package org.spongycastle.asn1.esf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class CommitmentTypeQualifier extends ASN1Encodable {
    private DERObjectIdentifier commitmentTypeIdentifier;
    private DEREncodable qualifier;

    public CommitmentTypeQualifier(DERObjectIdentifier commitmentTypeIdentifier) {
        this(commitmentTypeIdentifier, null);
    }

    public CommitmentTypeQualifier(DERObjectIdentifier commitmentTypeIdentifier, DEREncodable qualifier) {
        this.commitmentTypeIdentifier = commitmentTypeIdentifier;
        this.qualifier = qualifier;
    }

    public CommitmentTypeQualifier(ASN1Sequence as) {
        this.commitmentTypeIdentifier = (DERObjectIdentifier) as.getObjectAt(0);
        if (as.size() > 1) {
            this.qualifier = as.getObjectAt(1);
        }
    }

    public static CommitmentTypeQualifier getInstance(Object as) {
        if ((as instanceof CommitmentTypeQualifier) || as == null) {
            return (CommitmentTypeQualifier) as;
        }
        if (as instanceof ASN1Sequence) {
            return new CommitmentTypeQualifier((ASN1Sequence) as);
        }
        throw new IllegalArgumentException("unknown object in getInstance.");
    }

    public DERObjectIdentifier getCommitmentTypeIdentifier() {
        return this.commitmentTypeIdentifier;
    }

    public DEREncodable getQualifier() {
        return this.qualifier;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector dev = new ASN1EncodableVector();
        dev.add(this.commitmentTypeIdentifier);
        if (this.qualifier != null) {
            dev.add(this.qualifier);
        }
        return new DERSequence(dev);
    }
}
