package org.spongycastle.asn1.pkcs;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.X509Name;

public class IssuerAndSerialNumber extends ASN1Encodable {
    DERInteger certSerialNumber;
    X509Name name;

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new IssuerAndSerialNumber((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public IssuerAndSerialNumber(ASN1Sequence seq) {
        this.name = X509Name.getInstance(seq.getObjectAt(0));
        this.certSerialNumber = (DERInteger) seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(X509Name name, BigInteger certSerialNumber) {
        this.name = name;
        this.certSerialNumber = new DERInteger(certSerialNumber);
    }

    public IssuerAndSerialNumber(X509Name name, DERInteger certSerialNumber) {
        this.name = name;
        this.certSerialNumber = certSerialNumber;
    }

    public X509Name getName() {
        return this.name;
    }

    public DERInteger getCertificateSerialNumber() {
        return this.certSerialNumber;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.name);
        v.add(this.certSerialNumber);
        return new DERSequence(v);
    }
}
