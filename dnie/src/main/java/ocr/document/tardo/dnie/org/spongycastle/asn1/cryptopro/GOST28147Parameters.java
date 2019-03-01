package org.spongycastle.asn1.cryptopro;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class GOST28147Parameters extends ASN1Encodable {
    ASN1OctetString iv;
    DERObjectIdentifier paramSet;

    public static GOST28147Parameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST28147Parameters getInstance(Object obj) {
        if (obj == null || (obj instanceof GOST28147Parameters)) {
            return (GOST28147Parameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new GOST28147Parameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public GOST28147Parameters(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.iv = (ASN1OctetString) e.nextElement();
        this.paramSet = (DERObjectIdentifier) e.nextElement();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.iv);
        v.add(this.paramSet);
        return new DERSequence(v);
    }
}
