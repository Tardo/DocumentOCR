package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class DSTU4145BinaryField extends ASN1Object {
    /* renamed from: j */
    private int f452j;
    /* renamed from: k */
    private int f453k;
    /* renamed from: l */
    private int f454l;
    /* renamed from: m */
    private int f455m;

    public DSTU4145BinaryField(int i, int i2) {
        this(i, i2, 0, 0);
    }

    public DSTU4145BinaryField(int i, int i2, int i3, int i4) {
        this.f455m = i;
        this.f453k = i2;
        this.f452j = i3;
        this.f454l = i4;
    }

    private DSTU4145BinaryField(ASN1Sequence aSN1Sequence) {
        this.f455m = DERInteger.getInstance(aSN1Sequence.getObjectAt(0)).getPositiveValue().intValue();
        if (aSN1Sequence.getObjectAt(1) instanceof ASN1Integer) {
            this.f453k = ((ASN1Integer) aSN1Sequence.getObjectAt(1)).getPositiveValue().intValue();
        } else if (aSN1Sequence.getObjectAt(1) instanceof ASN1Sequence) {
            ASN1Sequence instance = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(1));
            this.f453k = DERInteger.getInstance(instance.getObjectAt(0)).getPositiveValue().intValue();
            this.f452j = DERInteger.getInstance(instance.getObjectAt(1)).getPositiveValue().intValue();
            this.f454l = DERInteger.getInstance(instance.getObjectAt(2)).getPositiveValue().intValue();
        } else {
            throw new IllegalArgumentException("object parse error");
        }
    }

    public static DSTU4145BinaryField getInstance(Object obj) {
        return obj instanceof DSTU4145BinaryField ? (DSTU4145BinaryField) obj : obj != null ? new DSTU4145BinaryField(ASN1Sequence.getInstance(obj)) : null;
    }

    public int getK1() {
        return this.f453k;
    }

    public int getK2() {
        return this.f452j;
    }

    public int getK3() {
        return this.f454l;
    }

    public int getM() {
        return this.f455m;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer((long) this.f455m));
        if (this.f452j == 0) {
            aSN1EncodableVector.add(new ASN1Integer((long) this.f453k));
        } else {
            ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
            aSN1EncodableVector2.add(new ASN1Integer((long) this.f453k));
            aSN1EncodableVector2.add(new ASN1Integer((long) this.f452j));
            aSN1EncodableVector2.add(new ASN1Integer((long) this.f454l));
            aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector2));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}
