package org.spongycastle.asn1.x9;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECFieldElement.F2m;
import org.spongycastle.math.ec.ECFieldElement.Fp;

public class X9FieldElement extends ASN1Encodable {
    private static X9IntegerConverter converter = new X9IntegerConverter();
    /* renamed from: f */
    protected ECFieldElement f565f;

    public X9FieldElement(ECFieldElement f) {
        this.f565f = f;
    }

    public X9FieldElement(BigInteger p, ASN1OctetString s) {
        this(new Fp(p, new BigInteger(1, s.getOctets())));
    }

    public X9FieldElement(int m, int k1, int k2, int k3, ASN1OctetString s) {
        this(new F2m(m, k1, k2, k3, new BigInteger(1, s.getOctets())));
    }

    public ECFieldElement getValue() {
        return this.f565f;
    }

    public DERObject toASN1Object() {
        return new DEROctetString(converter.integerToBytes(this.f565f.toBigInteger(), converter.getByteLength(this.f565f)));
    }
}
