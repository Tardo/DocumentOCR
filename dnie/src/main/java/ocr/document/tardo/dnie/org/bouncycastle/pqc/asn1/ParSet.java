package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class ParSet extends ASN1Object {
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    /* renamed from: h */
    private int[] f530h;
    /* renamed from: k */
    private int[] f531k;
    /* renamed from: t */
    private int f532t;
    /* renamed from: w */
    private int[] f533w;

    public ParSet(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        this.f532t = i;
        this.f530h = iArr;
        this.f533w = iArr2;
        this.f531k = iArr3;
    }

    private ParSet(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 4) {
            throw new IllegalArgumentException("sie of seqOfParams = " + aSN1Sequence.size());
        }
        this.f532t = checkBigIntegerInIntRangeAndPositive(((ASN1Integer) aSN1Sequence.getObjectAt(0)).getValue());
        ASN1Sequence aSN1Sequence2 = (ASN1Sequence) aSN1Sequence.getObjectAt(1);
        ASN1Sequence aSN1Sequence3 = (ASN1Sequence) aSN1Sequence.getObjectAt(2);
        ASN1Sequence aSN1Sequence4 = (ASN1Sequence) aSN1Sequence.getObjectAt(3);
        if (aSN1Sequence2.size() == this.f532t && aSN1Sequence3.size() == this.f532t && aSN1Sequence4.size() == this.f532t) {
            this.f530h = new int[aSN1Sequence2.size()];
            this.f533w = new int[aSN1Sequence3.size()];
            this.f531k = new int[aSN1Sequence4.size()];
            for (int i = 0; i < this.f532t; i++) {
                this.f530h[i] = checkBigIntegerInIntRangeAndPositive(((ASN1Integer) aSN1Sequence2.getObjectAt(i)).getValue());
                this.f533w[i] = checkBigIntegerInIntRangeAndPositive(((ASN1Integer) aSN1Sequence3.getObjectAt(i)).getValue());
                this.f531k[i] = checkBigIntegerInIntRangeAndPositive(((ASN1Integer) aSN1Sequence4.getObjectAt(i)).getValue());
            }
            return;
        }
        throw new IllegalArgumentException("invalid size of sequences");
    }

    private static int checkBigIntegerInIntRangeAndPositive(BigInteger bigInteger) {
        if (bigInteger.compareTo(BigInteger.valueOf(2147483647L)) <= 0 && bigInteger.compareTo(ZERO) > 0) {
            return bigInteger.intValue();
        }
        throw new IllegalArgumentException("BigInteger not in Range: " + bigInteger.toString());
    }

    public static ParSet getInstance(Object obj) {
        return obj instanceof ParSet ? (ParSet) obj : obj != null ? new ParSet(ASN1Sequence.getInstance(obj)) : null;
    }

    public int[] getH() {
        return Arrays.clone(this.f530h);
    }

    public int[] getK() {
        return Arrays.clone(this.f531k);
    }

    public int getT() {
        return this.f532t;
    }

    public int[] getW() {
        return Arrays.clone(this.f533w);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
        for (int i = 0; i < this.f530h.length; i++) {
            aSN1EncodableVector.add(new ASN1Integer((long) this.f530h[i]));
            aSN1EncodableVector2.add(new ASN1Integer((long) this.f533w[i]));
            aSN1EncodableVector3.add(new ASN1Integer((long) this.f531k[i]));
        }
        ASN1EncodableVector aSN1EncodableVector4 = new ASN1EncodableVector();
        aSN1EncodableVector4.add(new ASN1Integer((long) this.f532t));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector2));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector3));
        return new DERSequence(aSN1EncodableVector4);
    }
}
