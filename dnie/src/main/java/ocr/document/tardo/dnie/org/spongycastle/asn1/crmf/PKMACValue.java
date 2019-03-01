package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cmp.CMPObjectIdentifiers;
import org.spongycastle.asn1.cmp.PBMParameter;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class PKMACValue extends ASN1Encodable {
    private AlgorithmIdentifier algId;
    private DERBitString value;

    private PKMACValue(ASN1Sequence seq) {
        this.algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.value = DERBitString.getInstance(seq.getObjectAt(1));
    }

    public static PKMACValue getInstance(Object o) {
        if (o instanceof PKMACValue) {
            return (PKMACValue) o;
        }
        if (o instanceof ASN1Sequence) {
            return new PKMACValue((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public static PKMACValue getInstance(ASN1TaggedObject obj, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public PKMACValue(PBMParameter params, DERBitString value) {
        this(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, params), value);
    }

    public PKMACValue(AlgorithmIdentifier aid, DERBitString value) {
        this.algId = aid;
        this.value = value;
    }

    public AlgorithmIdentifier getAlgId() {
        return this.algId;
    }

    public DERBitString getValue() {
        return this.value;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algId);
        v.add(this.value);
        return new DERSequence(v);
    }
}
