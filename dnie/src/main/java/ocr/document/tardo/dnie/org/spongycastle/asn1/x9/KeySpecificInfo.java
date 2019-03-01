package org.spongycastle.asn1.x9;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class KeySpecificInfo extends ASN1Encodable {
    private DERObjectIdentifier algorithm;
    private ASN1OctetString counter;

    public KeySpecificInfo(DERObjectIdentifier algorithm, ASN1OctetString counter) {
        this.algorithm = algorithm;
        this.counter = counter;
    }

    public KeySpecificInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.algorithm = (DERObjectIdentifier) e.nextElement();
        this.counter = (ASN1OctetString) e.nextElement();
    }

    public DERObjectIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public ASN1OctetString getCounter() {
        return this.counter;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algorithm);
        v.add(this.counter);
        return new DERSequence(v);
    }
}
