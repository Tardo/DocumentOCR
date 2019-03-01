package org.spongycastle.asn1.esf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class CrlOcspRef extends ASN1Encodable {
    private CrlListID crlids;
    private OcspListID ocspids;
    private OtherRevRefs otherRev;

    public static CrlOcspRef getInstance(Object obj) {
        if (obj instanceof CrlOcspRef) {
            return (CrlOcspRef) obj;
        }
        if (obj != null) {
            return new CrlOcspRef(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("null value in getInstance");
    }

    private CrlOcspRef(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            DERTaggedObject o = (DERTaggedObject) e.nextElement();
            switch (o.getTagNo()) {
                case 0:
                    this.crlids = CrlListID.getInstance(o.getObject());
                    break;
                case 1:
                    this.ocspids = OcspListID.getInstance(o.getObject());
                    break;
                case 2:
                    this.otherRev = OtherRevRefs.getInstance(o.getObject());
                    break;
                default:
                    throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    public CrlOcspRef(CrlListID crlids, OcspListID ocspids, OtherRevRefs otherRev) {
        this.crlids = crlids;
        this.ocspids = ocspids;
        this.otherRev = otherRev;
    }

    public CrlListID getCrlids() {
        return this.crlids;
    }

    public OcspListID getOcspids() {
        return this.ocspids;
    }

    public OtherRevRefs getOtherRev() {
        return this.otherRev;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.crlids != null) {
            v.add(new DERTaggedObject(true, 0, this.crlids.toASN1Object()));
        }
        if (this.ocspids != null) {
            v.add(new DERTaggedObject(true, 1, this.ocspids.toASN1Object()));
        }
        if (this.otherRev != null) {
            v.add(new DERTaggedObject(true, 2, this.otherRev.toASN1Object()));
        }
        return new DERSequence(v);
    }
}
