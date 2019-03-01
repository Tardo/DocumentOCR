package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x500.X500Name;

public class ServiceLocator extends ASN1Encodable {
    X500Name issuer;
    DERObject locator;

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.issuer);
        if (this.locator != null) {
            v.add(this.locator);
        }
        return new DERSequence(v);
    }
}
