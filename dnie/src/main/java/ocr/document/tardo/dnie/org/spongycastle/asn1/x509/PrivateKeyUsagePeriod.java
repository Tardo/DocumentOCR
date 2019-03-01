package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class PrivateKeyUsagePeriod extends ASN1Encodable {
    private DERGeneralizedTime _notAfter;
    private DERGeneralizedTime _notBefore;

    public static PrivateKeyUsagePeriod getInstance(Object obj) {
        if (obj instanceof PrivateKeyUsagePeriod) {
            return (PrivateKeyUsagePeriod) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PrivateKeyUsagePeriod((ASN1Sequence) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    private PrivateKeyUsagePeriod(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            if (tObj.getTagNo() == 0) {
                this._notBefore = DERGeneralizedTime.getInstance(tObj, false);
            } else if (tObj.getTagNo() == 1) {
                this._notAfter = DERGeneralizedTime.getInstance(tObj, false);
            }
        }
    }

    public DERGeneralizedTime getNotBefore() {
        return this._notBefore;
    }

    public DERGeneralizedTime getNotAfter() {
        return this._notAfter;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this._notBefore != null) {
            v.add(new DERTaggedObject(false, 0, this._notBefore));
        }
        if (this._notAfter != null) {
            v.add(new DERTaggedObject(false, 1, this._notAfter));
        }
        return new DERSequence(v);
    }
}
