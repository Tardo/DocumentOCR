package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;

public class Pfx extends ASN1Encodable implements PKCSObjectIdentifiers {
    private ContentInfo contentInfo;
    private MacData macData = null;

    public Pfx(ASN1Sequence seq) {
        if (((DERInteger) seq.getObjectAt(0)).getValue().intValue() != 3) {
            throw new IllegalArgumentException("wrong version for PFX PDU");
        }
        this.contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));
        if (seq.size() == 3) {
            this.macData = MacData.getInstance(seq.getObjectAt(2));
        }
    }

    public Pfx(ContentInfo contentInfo, MacData macData) {
        this.contentInfo = contentInfo;
        this.macData = macData;
    }

    public ContentInfo getAuthSafe() {
        return this.contentInfo;
    }

    public MacData getMacData() {
        return this.macData;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERInteger(3));
        v.add(this.contentInfo);
        if (this.macData != null) {
            v.add(this.macData);
        }
        return new BERSequence(v);
    }
}
