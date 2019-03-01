package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;

public class CVCertSignature extends ASN1Encodable {
    DERApplicationSpecific cvcsig = null;

    public CVCertSignature(byte[] signatureContent) {
        this.cvcsig = new DERApplicationSpecific(55, signatureContent);
    }

    public CVCertSignature(DERApplicationSpecific derApp) throws IllegalArgumentException {
        if (derApp.getApplicationTag() != 55) {
            throw new IllegalArgumentException("Contains no Signature with tag 0x5F37");
        }
        this.cvcsig = derApp;
    }

    public byte[] getDEREncoded() {
        return this.cvcsig.getDEREncoded();
    }

    public byte[] getSignature() {
        return this.cvcsig.getContents();
    }

    public DERObject toASN1Object() {
        return this.cvcsig;
    }
}
