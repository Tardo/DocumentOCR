package org.spongycastle.asn1.x9;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class DHPublicKey extends ASN1Encodable {
    /* renamed from: y */
    private DERInteger f560y;

    public static DHPublicKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(DERInteger.getInstance(obj, explicit));
    }

    public static DHPublicKey getInstance(Object obj) {
        if (obj == null || (obj instanceof DHPublicKey)) {
            return (DHPublicKey) obj;
        }
        if (obj instanceof DERInteger) {
            return new DHPublicKey((DERInteger) obj);
        }
        throw new IllegalArgumentException("Invalid DHPublicKey: " + obj.getClass().getName());
    }

    public DHPublicKey(DERInteger y) {
        if (y == null) {
            throw new IllegalArgumentException("'y' cannot be null");
        }
        this.f560y = y;
    }

    public DERInteger getY() {
        return this.f560y;
    }

    public DERObject toASN1Object() {
        return this.f560y;
    }
}