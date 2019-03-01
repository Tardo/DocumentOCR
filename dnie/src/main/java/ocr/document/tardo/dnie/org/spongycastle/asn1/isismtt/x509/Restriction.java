package org.spongycastle.asn1.isismtt.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x500.DirectoryString;

public class Restriction extends ASN1Encodable {
    private DirectoryString restriction;

    public static Restriction getInstance(Object obj) {
        if (obj instanceof Restriction) {
            return (Restriction) obj;
        }
        if (obj instanceof ASN1String) {
            return new Restriction(DirectoryString.getInstance(obj));
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private Restriction(DirectoryString restriction) {
        this.restriction = restriction;
    }

    public Restriction(String restriction) {
        this.restriction = new DirectoryString(restriction);
    }

    public DirectoryString getRestriction() {
        return this.restriction;
    }

    public DERObject toASN1Object() {
        return this.restriction.toASN1Object();
    }
}
