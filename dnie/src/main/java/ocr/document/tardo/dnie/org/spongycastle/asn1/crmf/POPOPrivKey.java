package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.cms.EnvelopedData;

public class POPOPrivKey extends ASN1Encodable implements ASN1Choice {
    public static final int agreeMAC = 3;
    public static final int dhMAC = 2;
    public static final int encryptedKey = 4;
    public static final int subsequentMessage = 1;
    public static final int thisMessage = 0;
    private ASN1Encodable obj;
    private int tagNo;

    private POPOPrivKey(ASN1TaggedObject obj) {
        this.tagNo = obj.getTagNo();
        switch (this.tagNo) {
            case 0:
                this.obj = DERBitString.getInstance(obj, false);
                return;
            case 1:
                this.obj = SubsequentMessage.valueOf(DERInteger.getInstance(obj, false).getValue().intValue());
                return;
            case 2:
                this.obj = DERBitString.getInstance(obj, false);
                return;
            case 3:
                this.obj = PKMACValue.getInstance(obj, false);
                return;
            case 4:
                this.obj = EnvelopedData.getInstance(obj, false);
                return;
            default:
                throw new IllegalArgumentException("unknown tag in POPOPrivKey");
        }
    }

    public static POPOPrivKey getInstance(ASN1TaggedObject tagged, boolean isExplicit) {
        return new POPOPrivKey(ASN1TaggedObject.getInstance(tagged.getObject()));
    }

    public POPOPrivKey(SubsequentMessage msg) {
        this.tagNo = 1;
        this.obj = msg;
    }

    public int getType() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.obj;
    }

    public DERObject toASN1Object() {
        return new DERTaggedObject(false, this.tagNo, this.obj);
    }
}
