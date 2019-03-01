package org.spongycastle.asn1.isismtt.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.GeneralName;

public class AdmissionSyntax extends ASN1Encodable {
    private GeneralName admissionAuthority;
    private ASN1Sequence contentsOfAdmissions;

    public static AdmissionSyntax getInstance(Object obj) {
        if (obj == null || (obj instanceof AdmissionSyntax)) {
            return (AdmissionSyntax) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AdmissionSyntax((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private AdmissionSyntax(ASN1Sequence seq) {
        switch (seq.size()) {
            case 1:
                this.contentsOfAdmissions = ASN1Sequence.getInstance(seq.getObjectAt(0));
                return;
            case 2:
                this.admissionAuthority = GeneralName.getInstance(seq.getObjectAt(0));
                this.contentsOfAdmissions = ASN1Sequence.getInstance(seq.getObjectAt(1));
                return;
            default:
                throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public AdmissionSyntax(GeneralName admissionAuthority, ASN1Sequence contentsOfAdmissions) {
        this.admissionAuthority = admissionAuthority;
        this.contentsOfAdmissions = contentsOfAdmissions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (this.admissionAuthority != null) {
            vec.add(this.admissionAuthority);
        }
        vec.add(this.contentsOfAdmissions);
        return new DERSequence(vec);
    }

    public GeneralName getAdmissionAuthority() {
        return this.admissionAuthority;
    }

    public Admissions[] getContentsOfAdmissions() {
        Admissions[] admissions = new Admissions[this.contentsOfAdmissions.size()];
        int count = 0;
        Enumeration e = this.contentsOfAdmissions.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            admissions[count] = Admissions.getInstance(e.nextElement());
            count = count2;
        }
        return admissions;
    }
}
