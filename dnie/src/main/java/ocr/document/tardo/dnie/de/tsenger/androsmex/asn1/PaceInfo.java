package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class PaceInfo extends ASN1Encodable {
    private DERInteger parameterId = null;
    private DERObjectIdentifier protocol = null;
    private DERInteger version = null;

    public PaceInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.version = (DERInteger) seq.getObjectAt(1);
        if (seq.size() > 2) {
            this.parameterId = (DERInteger) seq.getObjectAt(2);
        }
    }

    public String getProtocolOID() {
        return this.protocol.toString();
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public Integer getParameterId() {
        if (this.parameterId == null) {
            return null;
        }
        return Integer.valueOf(this.parameterId.getValue().intValue());
    }

    public String toString() {
        return "PaceInfo\n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tParameterId: " + getParameterId() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.version);
        if (this.parameterId != null) {
            v.add(this.parameterId);
        }
        return new DERSequence(v);
    }
}
