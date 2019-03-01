package org.spongycastle.asn1.x9;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class X9FieldID extends ASN1Encodable implements X9ObjectIdentifiers {
    private DERObjectIdentifier id;
    private DERObject parameters;

    public X9FieldID(BigInteger primeP) {
        this.id = prime_field;
        this.parameters = new DERInteger(primeP);
    }

    public X9FieldID(int m, int k1, int k2, int k3) {
        this.id = characteristic_two_field;
        ASN1EncodableVector fieldIdParams = new ASN1EncodableVector();
        fieldIdParams.add(new DERInteger(m));
        if (k2 == 0) {
            fieldIdParams.add(tpBasis);
            fieldIdParams.add(new DERInteger(k1));
        } else {
            fieldIdParams.add(ppBasis);
            ASN1EncodableVector pentanomialParams = new ASN1EncodableVector();
            pentanomialParams.add(new DERInteger(k1));
            pentanomialParams.add(new DERInteger(k2));
            pentanomialParams.add(new DERInteger(k3));
            fieldIdParams.add(new DERSequence(pentanomialParams));
        }
        this.parameters = new DERSequence(fieldIdParams);
    }

    public X9FieldID(ASN1Sequence seq) {
        this.id = (DERObjectIdentifier) seq.getObjectAt(0);
        this.parameters = (DERObject) seq.getObjectAt(1);
    }

    public DERObjectIdentifier getIdentifier() {
        return this.id;
    }

    public DERObject getParameters() {
        return this.parameters;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.id);
        v.add(this.parameters);
        return new DERSequence(v);
    }
}
