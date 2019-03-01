package org.spongycastle.asn1.x9;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class OtherInfo extends ASN1Encodable {
    private KeySpecificInfo keyInfo;
    private ASN1OctetString partyAInfo;
    private ASN1OctetString suppPubInfo;

    public OtherInfo(KeySpecificInfo keyInfo, ASN1OctetString partyAInfo, ASN1OctetString suppPubInfo) {
        this.keyInfo = keyInfo;
        this.partyAInfo = partyAInfo;
        this.suppPubInfo = suppPubInfo;
    }

    public OtherInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.keyInfo = new KeySpecificInfo((ASN1Sequence) e.nextElement());
        while (e.hasMoreElements()) {
            DERTaggedObject o = (DERTaggedObject) e.nextElement();
            if (o.getTagNo() == 0) {
                this.partyAInfo = (ASN1OctetString) o.getObject();
            } else if (o.getTagNo() == 2) {
                this.suppPubInfo = (ASN1OctetString) o.getObject();
            }
        }
    }

    public KeySpecificInfo getKeyInfo() {
        return this.keyInfo;
    }

    public ASN1OctetString getPartyAInfo() {
        return this.partyAInfo;
    }

    public ASN1OctetString getSuppPubInfo() {
        return this.suppPubInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.keyInfo);
        if (this.partyAInfo != null) {
            v.add(new DERTaggedObject(0, this.partyAInfo));
        }
        v.add(new DERTaggedObject(2, this.suppPubInfo));
        return new DERSequence(v);
    }
}
