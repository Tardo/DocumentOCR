package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class Target extends ASN1Encodable implements ASN1Choice {
    public static final int targetGroup = 1;
    public static final int targetName = 0;
    private GeneralName targGroup;
    private GeneralName targName;

    public static Target getInstance(Object obj) {
        if (obj instanceof Target) {
            return (Target) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new Target((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass());
    }

    private Target(ASN1TaggedObject tagObj) {
        switch (tagObj.getTagNo()) {
            case 0:
                this.targName = GeneralName.getInstance(tagObj, true);
                return;
            case 1:
                this.targGroup = GeneralName.getInstance(tagObj, true);
                return;
            default:
                throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
        }
    }

    public Target(int type, GeneralName name) {
        this(new DERTaggedObject(type, name));
    }

    public GeneralName getTargetGroup() {
        return this.targGroup;
    }

    public GeneralName getTargetName() {
        return this.targName;
    }

    public DERObject toASN1Object() {
        if (this.targName != null) {
            return new DERTaggedObject(true, 0, this.targName);
        }
        return new DERTaggedObject(true, 1, this.targGroup);
    }
}
