package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class Targets extends ASN1Encodable {
    private ASN1Sequence targets;

    public static Targets getInstance(Object obj) {
        if (obj instanceof Targets) {
            return (Targets) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Targets((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass());
    }

    private Targets(ASN1Sequence targets) {
        this.targets = targets;
    }

    public Targets(Target[] targets) {
        this.targets = new DERSequence((ASN1Encodable[]) targets);
    }

    public Target[] getTargets() {
        Target[] targs = new Target[this.targets.size()];
        int count = 0;
        Enumeration e = this.targets.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            targs[count] = Target.getInstance(e.nextElement());
            count = count2;
        }
        return targs;
    }

    public DERObject toASN1Object() {
        return this.targets;
    }
}
