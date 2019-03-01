package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public abstract class AmPublicKey extends ASN1Encodable {
    private DERObjectIdentifier oid06 = null;
    protected ASN1EncodableVector vec = new ASN1EncodableVector();

    protected abstract void decode(DERSequence dERSequence);

    public AmPublicKey(String oidString) {
        this.oid06 = new DERObjectIdentifier(oidString);
        this.vec.add(this.oid06);
    }

    public AmPublicKey(DERSequence seq) {
        this.oid06 = (DERObjectIdentifier) seq.getObjectAt(0);
        this.vec.add(this.oid06);
    }

    public DERObject toASN1Object() {
        return new DERApplicationSpecific(73, this.vec);
    }

    public String getOID() {
        return this.oid06.toString();
    }
}
