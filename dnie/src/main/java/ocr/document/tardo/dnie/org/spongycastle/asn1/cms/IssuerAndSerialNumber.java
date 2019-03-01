package org.spongycastle.asn1.cms;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.X509Name;

public class IssuerAndSerialNumber extends ASN1Encodable {
    private X500Name name;
    private DERInteger serialNumber;

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new IssuerAndSerialNumber((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Illegal object in IssuerAndSerialNumber: " + obj.getClass().getName());
    }

    public IssuerAndSerialNumber(ASN1Sequence seq) {
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.serialNumber = (DERInteger) seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(X500Name name, BigInteger serialNumber) {
        this.name = name;
        this.serialNumber = new DERInteger(serialNumber);
    }

    public IssuerAndSerialNumber(X509Name name, BigInteger serialNumber) {
        this.name = X500Name.getInstance(name);
        this.serialNumber = new DERInteger(serialNumber);
    }

    public IssuerAndSerialNumber(X509Name name, DERInteger serialNumber) {
        this.name = X500Name.getInstance(name);
        this.serialNumber = serialNumber;
    }

    public X500Name getName() {
        return this.name;
    }

    public DERInteger getSerialNumber() {
        return this.serialNumber;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.name);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
