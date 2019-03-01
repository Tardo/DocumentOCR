package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class AccessDescription extends ASN1Encodable {
    public static final DERObjectIdentifier id_ad_caIssuers = new DERObjectIdentifier("1.3.6.1.5.5.7.48.2");
    public static final DERObjectIdentifier id_ad_ocsp = new DERObjectIdentifier("1.3.6.1.5.5.7.48.1");
    GeneralName accessLocation = null;
    DERObjectIdentifier accessMethod = null;

    public static AccessDescription getInstance(Object obj) {
        if (obj instanceof AccessDescription) {
            return (AccessDescription) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AccessDescription((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AccessDescription(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("wrong number of elements in sequence");
        }
        this.accessMethod = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.accessLocation = GeneralName.getInstance(seq.getObjectAt(1));
    }

    public AccessDescription(DERObjectIdentifier oid, GeneralName location) {
        this.accessMethod = oid;
        this.accessLocation = location;
    }

    public DERObjectIdentifier getAccessMethod() {
        return this.accessMethod;
    }

    public GeneralName getAccessLocation() {
        return this.accessLocation;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector accessDescription = new ASN1EncodableVector();
        accessDescription.add(this.accessMethod);
        accessDescription.add(this.accessLocation);
        return new DERSequence(accessDescription);
    }

    public String toString() {
        return "AccessDescription: Oid(" + this.accessMethod.getId() + ")";
    }
}
