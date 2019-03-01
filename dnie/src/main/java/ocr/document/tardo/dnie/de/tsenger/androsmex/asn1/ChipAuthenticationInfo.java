package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class ChipAuthenticationInfo extends ASN1Encodable {
    private DERInteger keyId = null;
    private DERObjectIdentifier protocol = null;
    private DERInteger version = null;

    public ChipAuthenticationInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.version = (DERInteger) seq.getObjectAt(1);
        if (seq.size() > 2) {
            this.keyId = (DERInteger) seq.getObjectAt(2);
        }
    }

    public String getProtocolOID() {
        return this.protocol.toString();
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public int getKeyId() {
        if (this.keyId == null) {
            return -1;
        }
        return this.keyId.getValue().intValue();
    }

    public String toString() {
        return "ChipAuthenticationInfo \n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tKeyId: " + getKeyId() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.version);
        if (this.keyId != null) {
            v.add(this.keyId);
        }
        return new DERSequence(v);
    }
}
