package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class TargetInformation extends ASN1Encodable {
    private ASN1Sequence targets;

    public static TargetInformation getInstance(Object obj) {
        if (obj instanceof TargetInformation) {
            return (TargetInformation) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new TargetInformation((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass());
    }

    private TargetInformation(ASN1Sequence seq) {
        this.targets = seq;
    }

    public Targets[] getTargetsObjects() {
        Targets[] copy = new Targets[this.targets.size()];
        int count = 0;
        Enumeration e = this.targets.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            copy[count] = Targets.getInstance(e.nextElement());
            count = count2;
        }
        return copy;
    }

    public TargetInformation(Targets targets) {
        this.targets = new DERSequence((DEREncodable) targets);
    }

    public TargetInformation(Target[] targets) {
        this(new Targets(targets));
    }

    public DERObject toASN1Object() {
        return this.targets;
    }
}
