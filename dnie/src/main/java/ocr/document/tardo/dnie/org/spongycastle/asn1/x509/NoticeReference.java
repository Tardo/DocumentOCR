package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class NoticeReference extends ASN1Encodable {
    private ASN1Sequence noticeNumbers;
    private DisplayText organization;

    public NoticeReference(String orgName, Vector numbers) {
        this.organization = new DisplayText(orgName);
        Object o = numbers.elementAt(0);
        ASN1EncodableVector av = new ASN1EncodableVector();
        if (o instanceof Integer) {
            Enumeration it = numbers.elements();
            while (it.hasMoreElements()) {
                av.add(new DERInteger(((Integer) it.nextElement()).intValue()));
            }
        }
        this.noticeNumbers = new DERSequence(av);
    }

    public NoticeReference(String orgName, ASN1Sequence numbers) {
        this.organization = new DisplayText(orgName);
        this.noticeNumbers = numbers;
    }

    public NoticeReference(int displayTextType, String orgName, ASN1Sequence numbers) {
        this.organization = new DisplayText(displayTextType, orgName);
        this.noticeNumbers = numbers;
    }

    public NoticeReference(ASN1Sequence as) {
        if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
        this.organization = DisplayText.getInstance(as.getObjectAt(0));
        this.noticeNumbers = ASN1Sequence.getInstance(as.getObjectAt(1));
    }

    public static NoticeReference getInstance(Object as) {
        if (as instanceof NoticeReference) {
            return (NoticeReference) as;
        }
        if (as instanceof ASN1Sequence) {
            return new NoticeReference((ASN1Sequence) as);
        }
        throw new IllegalArgumentException("unknown object in getInstance.");
    }

    public DisplayText getOrganization() {
        return this.organization;
    }

    public ASN1Sequence getNoticeNumbers() {
        return this.noticeNumbers;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector av = new ASN1EncodableVector();
        av.add(this.organization);
        av.add(this.noticeNumbers);
        return new DERSequence(av);
    }
}
