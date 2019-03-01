package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class ChipAuthenticationDomainParameterInfo extends ASN1Encodable {
    private AlgorithmIdentifier domainParameter = null;
    private DERInteger keyId = null;
    private DERObjectIdentifier protocol = null;

    public ChipAuthenticationDomainParameterInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.keyId = (DERInteger) seq.getObjectAt(2);
        }
    }

    public String getProtocolOID() {
        return this.protocol.toString();
    }

    public AlgorithmIdentifier getDomainParameter() {
        return this.domainParameter;
    }

    public int getKeyId() {
        if (this.keyId == null) {
            return -1;
        }
        return this.keyId.getValue().intValue();
    }

    public String toString() {
        return "ChipAuthenticationDomainParameterInfo \n\tOID: " + getProtocolOID() + "\n\tDomainParameter: \n\t\t" + getDomainParameter().getAlgorithm() + "\n\t\t" + getDomainParameter().getParameters() + "\n\tKeyID " + getKeyId() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.domainParameter);
        if (this.keyId != null) {
            v.add(this.keyId);
        }
        return new DERSequence(v);
    }
}
