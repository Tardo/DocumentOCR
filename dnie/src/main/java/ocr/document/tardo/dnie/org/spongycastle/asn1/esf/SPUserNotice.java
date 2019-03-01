package org.spongycastle.asn1.esf;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.DisplayText;
import org.spongycastle.asn1.x509.NoticeReference;

public class SPUserNotice {
    private DisplayText explicitText;
    private NoticeReference noticeRef;

    public static SPUserNotice getInstance(Object obj) {
        if (obj == null || (obj instanceof SPUserNotice)) {
            return (SPUserNotice) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SPUserNotice((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in 'SPUserNotice' factory : " + obj.getClass().getName() + ".");
    }

    public SPUserNotice(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            DEREncodable object = (DEREncodable) e.nextElement();
            if (object instanceof NoticeReference) {
                this.noticeRef = NoticeReference.getInstance(object);
            } else if (object instanceof DisplayText) {
                this.explicitText = DisplayText.getInstance(object);
            } else {
                throw new IllegalArgumentException("Invalid element in 'SPUserNotice'.");
            }
        }
    }

    public SPUserNotice(NoticeReference noticeRef, DisplayText explicitText) {
        this.noticeRef = noticeRef;
        this.explicitText = explicitText;
    }

    public NoticeReference getNoticeRef() {
        return this.noticeRef;
    }

    public DisplayText getExplicitText() {
        return this.explicitText;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.noticeRef != null) {
            v.add(this.noticeRef);
        }
        if (this.explicitText != null) {
            v.add(this.explicitText);
        }
        return new DERSequence(v);
    }
}
