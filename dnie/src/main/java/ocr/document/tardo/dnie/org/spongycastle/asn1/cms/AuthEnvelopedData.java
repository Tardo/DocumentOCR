package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class AuthEnvelopedData extends ASN1Encodable {
    private ASN1Set authAttrs;
    private EncryptedContentInfo authEncryptedContentInfo;
    private ASN1OctetString mac;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private ASN1Set unauthAttrs;
    private DERInteger version;

    public AuthEnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo authEncryptedContentInfo, ASN1Set authAttrs, ASN1OctetString mac, ASN1Set unauthAttrs) {
        this.version = new DERInteger(0);
        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.authEncryptedContentInfo = authEncryptedContentInfo;
        this.authAttrs = authAttrs;
        this.mac = mac;
        this.unauthAttrs = unauthAttrs;
    }

    public AuthEnvelopedData(ASN1Sequence seq) {
        int index = 0 + 1;
        this.version = (DERInteger) seq.getObjectAt(0).getDERObject();
        int index2 = index + 1;
        DERObject tmp = seq.getObjectAt(index).getDERObject();
        if (tmp instanceof ASN1TaggedObject) {
            this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject) tmp, false);
            index = index2 + 1;
            tmp = seq.getObjectAt(index2).getDERObject();
            index2 = index;
        }
        this.recipientInfos = ASN1Set.getInstance(tmp);
        index = index2 + 1;
        this.authEncryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(index2).getDERObject());
        index2 = index + 1;
        tmp = seq.getObjectAt(index).getDERObject();
        if (tmp instanceof ASN1TaggedObject) {
            this.authAttrs = ASN1Set.getInstance((ASN1TaggedObject) tmp, false);
            index = index2 + 1;
            tmp = seq.getObjectAt(index2).getDERObject();
            index2 = index;
        }
        this.mac = ASN1OctetString.getInstance(tmp);
        if (seq.size() > index2) {
            index = index2 + 1;
            this.unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject) seq.getObjectAt(index2).getDERObject(), false);
            index2 = index;
        }
    }

    public static AuthEnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthEnvelopedData getInstance(Object obj) {
        if (obj == null || (obj instanceof AuthEnvelopedData)) {
            return (AuthEnvelopedData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AuthEnvelopedData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid AuthEnvelopedData: " + obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public OriginatorInfo getOriginatorInfo() {
        return this.originatorInfo;
    }

    public ASN1Set getRecipientInfos() {
        return this.recipientInfos;
    }

    public EncryptedContentInfo getAuthEncryptedContentInfo() {
        return this.authEncryptedContentInfo;
    }

    public ASN1Set getAuthAttrs() {
        return this.authAttrs;
    }

    public ASN1OctetString getMac() {
        return this.mac;
    }

    public ASN1Set getUnauthAttrs() {
        return this.unauthAttrs;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        if (this.originatorInfo != null) {
            v.add(new DERTaggedObject(false, 0, this.originatorInfo));
        }
        v.add(this.recipientInfos);
        v.add(this.authEncryptedContentInfo);
        if (this.authAttrs != null) {
            v.add(new DERTaggedObject(false, 1, this.authAttrs));
        }
        v.add(this.mac);
        if (this.unauthAttrs != null) {
            v.add(new DERTaggedObject(false, 2, this.unauthAttrs));
        }
        return new BERSequence(v);
    }
}
