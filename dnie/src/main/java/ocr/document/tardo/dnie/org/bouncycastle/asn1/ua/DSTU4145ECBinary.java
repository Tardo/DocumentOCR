package org.bouncycastle.asn1.ua;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.util.Arrays;

public class DSTU4145ECBinary extends ASN1Object {
    /* renamed from: a */
    ASN1Integer f456a;
    /* renamed from: b */
    ASN1OctetString f457b;
    ASN1OctetString bp;
    /* renamed from: f */
    DSTU4145BinaryField f458f;
    /* renamed from: n */
    ASN1Integer f459n;
    BigInteger version = BigInteger.valueOf(0);

    private DSTU4145ECBinary(ASN1Sequence aSN1Sequence) {
        int i = 0;
        if (aSN1Sequence.getObjectAt(0) instanceof ASN1TaggedObject) {
            ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) aSN1Sequence.getObjectAt(0);
            if (aSN1TaggedObject.isExplicit() && aSN1TaggedObject.getTagNo() == 0) {
                this.version = DERInteger.getInstance(aSN1TaggedObject.getLoadedObject()).getValue();
                i = 1;
            } else {
                throw new IllegalArgumentException("object parse error");
            }
        }
        this.f458f = DSTU4145BinaryField.getInstance(aSN1Sequence.getObjectAt(i));
        i++;
        this.f456a = DERInteger.getInstance(aSN1Sequence.getObjectAt(i));
        i++;
        this.f457b = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i));
        i++;
        this.f459n = DERInteger.getInstance(aSN1Sequence.getObjectAt(i));
        this.bp = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i + 1));
    }

    public DSTU4145ECBinary(ECDomainParameters eCDomainParameters) {
        if (eCDomainParameters.getCurve() instanceof F2m) {
            ECCurve eCCurve = (F2m) eCDomainParameters.getCurve();
            this.f458f = new DSTU4145BinaryField(eCCurve.getM(), eCCurve.getK1(), eCCurve.getK2(), eCCurve.getK3());
            this.f456a = new ASN1Integer(eCCurve.getA().toBigInteger());
            X9IntegerConverter x9IntegerConverter = new X9IntegerConverter();
            this.f457b = new DEROctetString(x9IntegerConverter.integerToBytes(eCCurve.getB().toBigInteger(), x9IntegerConverter.getByteLength(eCCurve)));
            this.f459n = new ASN1Integer(eCDomainParameters.getN());
            this.bp = new DEROctetString(DSTU4145PointEncoder.encodePoint(eCDomainParameters.getG()));
            return;
        }
        throw new IllegalArgumentException("only binary domain is possible");
    }

    public static DSTU4145ECBinary getInstance(Object obj) {
        return obj instanceof DSTU4145ECBinary ? (DSTU4145ECBinary) obj : obj != null ? new DSTU4145ECBinary(ASN1Sequence.getInstance(obj)) : null;
    }

    public BigInteger getA() {
        return this.f456a.getValue();
    }

    public byte[] getB() {
        return Arrays.clone(this.f457b.getOctets());
    }

    public DSTU4145BinaryField getField() {
        return this.f458f;
    }

    public byte[] getG() {
        return Arrays.clone(this.bp.getOctets());
    }

    public BigInteger getN() {
        return this.f459n.getValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        if (this.version.compareTo(BigInteger.valueOf(0)) != 0) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 0, new ASN1Integer(this.version)));
        }
        aSN1EncodableVector.add(this.f458f);
        aSN1EncodableVector.add(this.f456a);
        aSN1EncodableVector.add(this.f457b);
        aSN1EncodableVector.add(this.f459n);
        aSN1EncodableVector.add(this.bp);
        return new DERSequence(aSN1EncodableVector);
    }
}
