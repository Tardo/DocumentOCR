package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class RecipientInfo extends ASN1Encodable implements ASN1Choice {
    DEREncodable info;

    public RecipientInfo(KeyTransRecipientInfo info) {
        this.info = info;
    }

    public RecipientInfo(KeyAgreeRecipientInfo info) {
        this.info = new DERTaggedObject(false, 1, info);
    }

    public RecipientInfo(KEKRecipientInfo info) {
        this.info = new DERTaggedObject(false, 2, info);
    }

    public RecipientInfo(PasswordRecipientInfo info) {
        this.info = new DERTaggedObject(false, 3, info);
    }

    public RecipientInfo(OtherRecipientInfo info) {
        this.info = new DERTaggedObject(false, 4, info);
    }

    public RecipientInfo(DERObject info) {
        this.info = info;
    }

    public static RecipientInfo getInstance(Object o) {
        if (o == null || (o instanceof RecipientInfo)) {
            return (RecipientInfo) o;
        }
        if (o instanceof ASN1Sequence) {
            return new RecipientInfo((ASN1Sequence) o);
        }
        if (o instanceof ASN1TaggedObject) {
            return new RecipientInfo((ASN1TaggedObject) o);
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public DERInteger getVersion() {
        if (!(this.info instanceof ASN1TaggedObject)) {
            return KeyTransRecipientInfo.getInstance(this.info).getVersion();
        }
        ASN1TaggedObject o = this.info;
        switch (o.getTagNo()) {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(o, false).getVersion();
            case 2:
                return getKEKInfo(o).getVersion();
            case 3:
                return PasswordRecipientInfo.getInstance(o, false).getVersion();
            case 4:
                return new DERInteger(0);
            default:
                throw new IllegalStateException("unknown tag");
        }
    }

    public boolean isTagged() {
        return this.info instanceof ASN1TaggedObject;
    }

    public DEREncodable getInfo() {
        if (!(this.info instanceof ASN1TaggedObject)) {
            return KeyTransRecipientInfo.getInstance(this.info);
        }
        ASN1TaggedObject o = this.info;
        switch (o.getTagNo()) {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(o, false);
            case 2:
                return getKEKInfo(o);
            case 3:
                return PasswordRecipientInfo.getInstance(o, false);
            case 4:
                return OtherRecipientInfo.getInstance(o, false);
            default:
                throw new IllegalStateException("unknown tag");
        }
    }

    private KEKRecipientInfo getKEKInfo(ASN1TaggedObject o) {
        if (o.isExplicit()) {
            return KEKRecipientInfo.getInstance(o, true);
        }
        return KEKRecipientInfo.getInstance(o, false);
    }

    public DERObject toASN1Object() {
        return this.info.getDERObject();
    }
}
