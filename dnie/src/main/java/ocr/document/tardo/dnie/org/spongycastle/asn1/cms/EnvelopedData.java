package org.spongycastle.asn1.cms;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class EnvelopedData extends ASN1Encodable {
    private EncryptedContentInfo encryptedContentInfo;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private ASN1Set unprotectedAttrs;
    private DERInteger version;

    public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo encryptedContentInfo, ASN1Set unprotectedAttrs) {
        if (originatorInfo == null && unprotectedAttrs == null) {
            this.version = new DERInteger(0);
            Enumeration e = recipientInfos.getObjects();
            while (e.hasMoreElements()) {
                if (!RecipientInfo.getInstance(e.nextElement()).getVersion().equals(this.version)) {
                    this.version = new DERInteger(2);
                    break;
                }
            }
        }
        this.version = new DERInteger(2);
        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    public EnvelopedData(ASN1Sequence seq) {
        int index = 0 + 1;
        this.version = (DERInteger) seq.getObjectAt(0);
        int index2 = index + 1;
        DEREncodable tmp = seq.getObjectAt(index);
        if (tmp instanceof ASN1TaggedObject) {
            this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject) tmp, false);
            index = index2 + 1;
            tmp = seq.getObjectAt(index2);
            index2 = index;
        }
        this.recipientInfos = ASN1Set.getInstance(tmp);
        index = index2 + 1;
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(index2));
        if (seq.size() > index) {
            this.unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject) seq.getObjectAt(index), false);
        }
    }

    public static EnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EnvelopedData getInstance(Object obj) {
        if (obj == null || (obj instanceof EnvelopedData)) {
            return (EnvelopedData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new EnvelopedData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid EnvelopedData: " + obj.getClass().getName());
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

    public EncryptedContentInfo getEncryptedContentInfo() {
        return this.encryptedContentInfo;
    }

    public ASN1Set getUnprotectedAttrs() {
        return this.unprotectedAttrs;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        if (this.originatorInfo != null) {
            v.add(new DERTaggedObject(false, 0, this.originatorInfo));
        }
        v.add(this.recipientInfos);
        v.add(this.encryptedContentInfo);
        if (this.unprotectedAttrs != null) {
            v.add(new DERTaggedObject(false, 1, this.unprotectedAttrs));
        }
        return new BERSequence(v);
    }
}
