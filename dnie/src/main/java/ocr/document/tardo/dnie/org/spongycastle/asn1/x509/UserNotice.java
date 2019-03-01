package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class UserNotice extends ASN1Encodable {
    private DisplayText explicitText;
    private NoticeReference noticeRef;

    public UserNotice(NoticeReference noticeRef, DisplayText explicitText) {
        this.noticeRef = noticeRef;
        this.explicitText = explicitText;
    }

    public UserNotice(NoticeReference noticeRef, String str) {
        this.noticeRef = noticeRef;
        this.explicitText = new DisplayText(str);
    }

    public UserNotice(ASN1Sequence as) {
        if (as.size() == 2) {
            this.noticeRef = NoticeReference.getInstance(as.getObjectAt(0));
            this.explicitText = DisplayText.getInstance(as.getObjectAt(1));
        } else if (as.size() != 1) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        } else if (as.getObjectAt(0).getDERObject() instanceof ASN1Sequence) {
            this.noticeRef = NoticeReference.getInstance(as.getObjectAt(0));
        } else {
            this.explicitText = DisplayText.getInstance(as.getObjectAt(0));
        }
    }

    public NoticeReference getNoticeRef() {
        return this.noticeRef;
    }

    public DisplayText getExplicitText() {
        return this.explicitText;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector av = new ASN1EncodableVector();
        if (this.noticeRef != null) {
            av.add(this.noticeRef);
        }
        if (this.explicitText != null) {
            av.add(this.explicitText);
        }
        return new DERSequence(av);
    }
}
