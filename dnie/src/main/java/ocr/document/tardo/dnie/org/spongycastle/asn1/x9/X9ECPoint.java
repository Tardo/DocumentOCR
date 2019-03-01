package org.spongycastle.asn1.x9;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;

public class X9ECPoint extends ASN1Encodable {
    /* renamed from: p */
    ECPoint f564p;

    public X9ECPoint(ECPoint p) {
        this.f564p = p;
    }

    public X9ECPoint(ECCurve c, ASN1OctetString s) {
        this.f564p = c.decodePoint(s.getOctets());
    }

    public ECPoint getPoint() {
        return this.f564p;
    }

    public DERObject toASN1Object() {
        return new DEROctetString(this.f564p.getEncoded());
    }
}
