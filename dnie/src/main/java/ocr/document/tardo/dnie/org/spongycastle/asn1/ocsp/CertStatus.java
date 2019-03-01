package org.spongycastle.asn1.ocsp;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class CertStatus extends ASN1Encodable implements ASN1Choice {
    private int tagNo;
    private DEREncodable value;

    public CertStatus() {
        this.tagNo = 0;
        this.value = new DERNull();
    }

    public CertStatus(RevokedInfo info) {
        this.tagNo = 1;
        this.value = info;
    }

    public CertStatus(int tagNo, DEREncodable value) {
        this.tagNo = tagNo;
        this.value = value;
    }

    public CertStatus(ASN1TaggedObject choice) {
        this.tagNo = choice.getTagNo();
        switch (choice.getTagNo()) {
            case 0:
                this.value = new DERNull();
                return;
            case 1:
                this.value = RevokedInfo.getInstance(choice, false);
                return;
            case 2:
                this.value = new DERNull();
                return;
            default:
                return;
        }
    }

    public static CertStatus getInstance(Object obj) {
        if (obj == null || (obj instanceof CertStatus)) {
            return (CertStatus) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new CertStatus((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static CertStatus getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public DEREncodable getStatus() {
        return this.value;
    }

    public DERObject toASN1Object() {
        return new DERTaggedObject(false, this.tagNo, this.value);
    }
}
