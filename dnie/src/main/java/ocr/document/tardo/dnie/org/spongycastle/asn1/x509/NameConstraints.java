package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class NameConstraints extends ASN1Encodable {
    private ASN1Sequence excluded;
    private ASN1Sequence permitted;

    public NameConstraints(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 0:
                    this.permitted = ASN1Sequence.getInstance(o, false);
                    break;
                case 1:
                    this.excluded = ASN1Sequence.getInstance(o, false);
                    break;
                default:
                    break;
            }
        }
    }

    public NameConstraints(Vector permitted, Vector excluded) {
        if (permitted != null) {
            this.permitted = createSequence(permitted);
        }
        if (excluded != null) {
            this.excluded = createSequence(excluded);
        }
    }

    private DERSequence createSequence(Vector subtree) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        Enumeration e = subtree.elements();
        while (e.hasMoreElements()) {
            vec.add((GeneralSubtree) e.nextElement());
        }
        return new DERSequence(vec);
    }

    public ASN1Sequence getPermittedSubtrees() {
        return this.permitted;
    }

    public ASN1Sequence getExcludedSubtrees() {
        return this.excluded;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.permitted != null) {
            v.add(new DERTaggedObject(false, 0, this.permitted));
        }
        if (this.excluded != null) {
            v.add(new DERTaggedObject(false, 1, this.excluded));
        }
        return new DERSequence(v);
    }
}
