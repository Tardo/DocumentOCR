package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.GeneralName;

public class CertId extends ASN1Encodable {
    private GeneralName issuer;
    private DERInteger serialNumber;

    private CertId(ASN1Sequence seq) {
        this.issuer = GeneralName.getInstance(seq.getObjectAt(0));
        this.serialNumber = DERInteger.getInstance(seq.getObjectAt(1));
    }

    public static CertId getInstance(Object o) {
        if (o instanceof CertId) {
            return (CertId) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertId((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public static CertId getInstance(ASN1TaggedObject obj, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public GeneralName getIssuer() {
        return this.issuer;
    }

    public DERInteger getSerialNumber() {
        return this.serialNumber;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.issuer);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
