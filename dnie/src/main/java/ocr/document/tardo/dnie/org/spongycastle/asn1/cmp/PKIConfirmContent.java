package org.spongycastle.asn1.cmp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Null;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;

public class PKIConfirmContent extends ASN1Encodable {
    private ASN1Null val;

    private PKIConfirmContent(ASN1Null val) {
        this.val = val;
    }

    public static PKIConfirmContent getInstance(Object o) {
        if (o instanceof PKIConfirmContent) {
            return (PKIConfirmContent) o;
        }
        if (o instanceof ASN1Null) {
            return new PKIConfirmContent((ASN1Null) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIConfirmContent() {
        this.val = DERNull.INSTANCE;
    }

    public DERObject toASN1Object() {
        return this.val;
    }
}
