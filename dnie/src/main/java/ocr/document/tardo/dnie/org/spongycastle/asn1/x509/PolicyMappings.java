package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class PolicyMappings extends ASN1Encodable {
    ASN1Sequence seq = null;

    public PolicyMappings(ASN1Sequence seq) {
        this.seq = seq;
    }

    public PolicyMappings(Hashtable mappings) {
        ASN1EncodableVector dev = new ASN1EncodableVector();
        Enumeration it = mappings.keys();
        while (it.hasMoreElements()) {
            String idp = (String) it.nextElement();
            String sdp = (String) mappings.get(idp);
            ASN1EncodableVector dv = new ASN1EncodableVector();
            dv.add(new DERObjectIdentifier(idp));
            dv.add(new DERObjectIdentifier(sdp));
            dev.add(new DERSequence(dv));
        }
        this.seq = new DERSequence(dev);
    }

    public DERObject toASN1Object() {
        return this.seq;
    }
}
