package org.spongycastle.asn1.smime;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class SMIMECapabilityVector {
    private ASN1EncodableVector capabilities = new ASN1EncodableVector();

    public void addCapability(DERObjectIdentifier capability) {
        this.capabilities.add(new DERSequence((DEREncodable) capability));
    }

    public void addCapability(DERObjectIdentifier capability, int value) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(capability);
        v.add(new DERInteger(value));
        this.capabilities.add(new DERSequence(v));
    }

    public void addCapability(DERObjectIdentifier capability, DEREncodable params) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(capability);
        v.add(params);
        this.capabilities.add(new DERSequence(v));
    }

    public ASN1EncodableVector toASN1EncodableVector() {
        return this.capabilities;
    }
}
