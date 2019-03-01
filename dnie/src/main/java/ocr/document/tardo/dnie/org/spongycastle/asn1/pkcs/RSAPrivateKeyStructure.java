package org.spongycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class RSAPrivateKeyStructure extends ASN1Encodable {
    private BigInteger coefficient;
    private BigInteger exponent1;
    private BigInteger exponent2;
    private BigInteger modulus;
    private ASN1Sequence otherPrimeInfos;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger privateExponent;
    private BigInteger publicExponent;
    private int version;

    public static RSAPrivateKeyStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPrivateKeyStructure getInstance(Object obj) {
        if (obj instanceof RSAPrivateKeyStructure) {
            return (RSAPrivateKeyStructure) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new RSAPrivateKeyStructure((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public RSAPrivateKeyStructure(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger prime1, BigInteger prime2, BigInteger exponent1, BigInteger exponent2, BigInteger coefficient) {
        this.otherPrimeInfos = null;
        this.version = 0;
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public RSAPrivateKeyStructure(ASN1Sequence seq) {
        this.otherPrimeInfos = null;
        Enumeration e = seq.getObjects();
        BigInteger v = ((DERInteger) e.nextElement()).getValue();
        if (v.intValue() == 0 || v.intValue() == 1) {
            this.version = v.intValue();
            this.modulus = ((DERInteger) e.nextElement()).getValue();
            this.publicExponent = ((DERInteger) e.nextElement()).getValue();
            this.privateExponent = ((DERInteger) e.nextElement()).getValue();
            this.prime1 = ((DERInteger) e.nextElement()).getValue();
            this.prime2 = ((DERInteger) e.nextElement()).getValue();
            this.exponent1 = ((DERInteger) e.nextElement()).getValue();
            this.exponent2 = ((DERInteger) e.nextElement()).getValue();
            this.coefficient = ((DERInteger) e.nextElement()).getValue();
            if (e.hasMoreElements()) {
                this.otherPrimeInfos = (ASN1Sequence) e.nextElement();
                return;
            }
            return;
        }
        throw new IllegalArgumentException("wrong version for RSA private key");
    }

    public int getVersion() {
        return this.version;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    public BigInteger getPrivateExponent() {
        return this.privateExponent;
    }

    public BigInteger getPrime1() {
        return this.prime1;
    }

    public BigInteger getPrime2() {
        return this.prime2;
    }

    public BigInteger getExponent1() {
        return this.exponent1;
    }

    public BigInteger getExponent2() {
        return this.exponent2;
    }

    public BigInteger getCoefficient() {
        return this.coefficient;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(this.version));
        v.add(new DERInteger(getModulus()));
        v.add(new DERInteger(getPublicExponent()));
        v.add(new DERInteger(getPrivateExponent()));
        v.add(new DERInteger(getPrime1()));
        v.add(new DERInteger(getPrime2()));
        v.add(new DERInteger(getExponent1()));
        v.add(new DERInteger(getExponent2()));
        v.add(new DERInteger(getCoefficient()));
        if (this.otherPrimeInfos != null) {
            v.add(this.otherPrimeInfos);
        }
        return new DERSequence(v);
    }
}
