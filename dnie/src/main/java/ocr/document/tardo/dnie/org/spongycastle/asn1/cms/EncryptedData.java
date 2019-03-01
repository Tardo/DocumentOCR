package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class EncryptedData extends ASN1Encodable {
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set unprotectedAttrs;
    private DERInteger version;

    public static EncryptedData getInstance(Object o) {
        if (o instanceof EncryptedData) {
            return (EncryptedData) o;
        }
        if (o instanceof ASN1Sequence) {
            return new EncryptedData((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid EncryptedData: " + o.getClass().getName());
    }

    public EncryptedData(EncryptedContentInfo encInfo) {
        this(encInfo, null);
    }

    public EncryptedData(EncryptedContentInfo encInfo, ASN1Set unprotectedAttrs) {
        this.version = new DERInteger(unprotectedAttrs == null ? 0 : 2);
        this.encryptedContentInfo = encInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    private EncryptedData(ASN1Sequence seq) {
        this.version = DERInteger.getInstance(seq.getObjectAt(0));
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(1));
        if (seq.size() == 3) {
            this.unprotectedAttrs = ASN1Set.getInstance(seq.getObjectAt(2));
        }
    }

    public DERInteger getVersion() {
        return this.version;
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
        v.add(this.encryptedContentInfo);
        if (this.unprotectedAttrs != null) {
            v.add(new BERTaggedObject(false, 1, this.unprotectedAttrs));
        }
        return new BERSequence(v);
    }
}
