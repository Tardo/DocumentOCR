package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class PaceDomainParameterInfo extends ASN1Encodable {
    private AlgorithmIdentifier domainParameter = null;
    private DERInteger parameterId = null;
    private DERObjectIdentifier protocol = null;

    public PaceDomainParameterInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.parameterId = (DERInteger) seq.getObjectAt(2);
        }
    }

    public DERObjectIdentifier getProtocol() {
        return this.protocol;
    }

    public AlgorithmIdentifier getDomainParameter() {
        return this.domainParameter;
    }

    public int getParameterId() {
        if (this.parameterId == null) {
            return -1;
        }
        return this.parameterId.getValue().intValue();
    }

    public String toString() {
        return "PaceDomainParameterInfo\n\tOID: " + getProtocol() + "\n\tDomainParameter: \n\t\t" + getDomainParameter().getAlgorithm() + "\n\t\t" + getDomainParameter().getParameters() + "\n\tParameterId: " + getParameterId() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.domainParameter);
        if (this.parameterId != null) {
            v.add(this.parameterId);
        }
        return new DERSequence(v);
    }
}
