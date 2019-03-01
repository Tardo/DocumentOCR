package org.spongycastle.asn1.x9;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Null;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;

public class X962Parameters extends ASN1Encodable implements ASN1Choice {
    private DERObject params = null;

    public static X962Parameters getInstance(Object obj) {
        if (obj == null || (obj instanceof X962Parameters)) {
            return (X962Parameters) obj;
        }
        if (obj instanceof DERObject) {
            return new X962Parameters((DERObject) obj);
        }
        throw new IllegalArgumentException("unknown object in getInstance()");
    }

    public static X962Parameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public X962Parameters(X9ECParameters ecParameters) {
        this.params = ecParameters.getDERObject();
    }

    public X962Parameters(DERObjectIdentifier namedCurve) {
        this.params = namedCurve;
    }

    public X962Parameters(DERObject obj) {
        this.params = obj;
    }

    public boolean isNamedCurve() {
        return this.params instanceof DERObjectIdentifier;
    }

    public boolean isImplicitlyCA() {
        return this.params instanceof ASN1Null;
    }

    public DERObject getParameters() {
        return this.params;
    }

    public DERObject toASN1Object() {
        return this.params;
    }
}
