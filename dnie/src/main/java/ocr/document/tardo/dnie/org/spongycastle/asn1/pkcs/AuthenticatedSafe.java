package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERObject;

public class AuthenticatedSafe extends ASN1Encodable {
    ContentInfo[] info;

    public AuthenticatedSafe(ASN1Sequence seq) {
        this.info = new ContentInfo[seq.size()];
        for (int i = 0; i != this.info.length; i++) {
            this.info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }
    }

    public AuthenticatedSafe(ContentInfo[] info) {
        this.info = info;
    }

    public ContentInfo[] getContentInfo() {
        return this.info;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != this.info.length; i++) {
            v.add(this.info[i]);
        }
        return new BERSequence(v);
    }
}
