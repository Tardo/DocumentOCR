package org.spongycastle.asn1.x9;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECCurve.F2m;
import org.spongycastle.math.ec.ECCurve.Fp;

public class X9Curve extends ASN1Encodable implements X9ObjectIdentifiers {
    private ECCurve curve;
    private DERObjectIdentifier fieldIdentifier = null;
    private byte[] seed;

    public X9Curve(ECCurve curve) {
        this.curve = curve;
        this.seed = null;
        setFieldIdentifier();
    }

    public X9Curve(ECCurve curve, byte[] seed) {
        this.curve = curve;
        this.seed = seed;
        setFieldIdentifier();
    }

    public X9Curve(X9FieldID fieldID, ASN1Sequence seq) {
        this.fieldIdentifier = fieldID.getIdentifier();
        if (this.fieldIdentifier.equals(prime_field)) {
            BigInteger p = ((DERInteger) fieldID.getParameters()).getValue();
            this.curve = new Fp(p, new X9FieldElement(p, (ASN1OctetString) seq.getObjectAt(0)).getValue().toBigInteger(), new X9FieldElement(p, (ASN1OctetString) seq.getObjectAt(1)).getValue().toBigInteger());
        } else if (this.fieldIdentifier.equals(characteristic_two_field)) {
            int k1;
            DERSequence parameters = (DERSequence) fieldID.getParameters();
            int m = ((DERInteger) parameters.getObjectAt(0)).getValue().intValue();
            int k2 = 0;
            int k3 = 0;
            if (((DERObjectIdentifier) parameters.getObjectAt(1)).equals(tpBasis)) {
                k1 = ((DERInteger) parameters.getObjectAt(2)).getValue().intValue();
            } else {
                DERSequence pentanomial = (DERSequence) parameters.getObjectAt(2);
                k1 = ((DERInteger) pentanomial.getObjectAt(0)).getValue().intValue();
                k2 = ((DERInteger) pentanomial.getObjectAt(1)).getValue().intValue();
                k3 = ((DERInteger) pentanomial.getObjectAt(2)).getValue().intValue();
            }
            X9FieldElement x9A = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString) seq.getObjectAt(0));
            X9FieldElement x9B = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString) seq.getObjectAt(1));
            this.curve = new F2m(m, k1, k2, k3, x9A.getValue().toBigInteger(), x9B.getValue().toBigInteger());
        }
        if (seq.size() == 3) {
            this.seed = ((DERBitString) seq.getObjectAt(2)).getBytes();
        }
    }

    private void setFieldIdentifier() {
        if (this.curve instanceof Fp) {
            this.fieldIdentifier = prime_field;
        } else if (this.curve instanceof F2m) {
            this.fieldIdentifier = characteristic_two_field;
        } else {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.fieldIdentifier.equals(prime_field)) {
            v.add(new X9FieldElement(this.curve.getA()).getDERObject());
            v.add(new X9FieldElement(this.curve.getB()).getDERObject());
        } else if (this.fieldIdentifier.equals(characteristic_two_field)) {
            v.add(new X9FieldElement(this.curve.getA()).getDERObject());
            v.add(new X9FieldElement(this.curve.getB()).getDERObject());
        }
        if (this.seed != null) {
            v.add(new DERBitString(this.seed));
        }
        return new DERSequence(v);
    }
}
