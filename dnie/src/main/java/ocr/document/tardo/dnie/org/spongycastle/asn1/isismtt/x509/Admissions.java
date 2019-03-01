package org.spongycastle.asn1.isismtt.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.GeneralName;

public class Admissions extends ASN1Encodable {
    private GeneralName admissionAuthority;
    private NamingAuthority namingAuthority;
    private ASN1Sequence professionInfos;

    public static Admissions getInstance(Object obj) {
        if (obj == null || (obj instanceof Admissions)) {
            return (Admissions) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Admissions((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private Admissions(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        DEREncodable o = (DEREncodable) e.nextElement();
        if (o instanceof ASN1TaggedObject) {
            switch (((ASN1TaggedObject) o).getTagNo()) {
                case 0:
                    this.admissionAuthority = GeneralName.getInstance((ASN1TaggedObject) o, true);
                    break;
                case 1:
                    this.namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject) o, true);
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject) o).getTagNo());
            }
            o = (DEREncodable) e.nextElement();
        }
        if (o instanceof ASN1TaggedObject) {
            switch (((ASN1TaggedObject) o).getTagNo()) {
                case 1:
                    this.namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject) o, true);
                    o = (DEREncodable) e.nextElement();
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject) o).getTagNo());
            }
        }
        this.professionInfos = ASN1Sequence.getInstance(o);
        if (e.hasMoreElements()) {
            throw new IllegalArgumentException("Bad object encountered: " + e.nextElement().getClass());
        }
    }

    public Admissions(GeneralName admissionAuthority, NamingAuthority namingAuthority, ProfessionInfo[] professionInfos) {
        this.admissionAuthority = admissionAuthority;
        this.namingAuthority = namingAuthority;
        this.professionInfos = new DERSequence((ASN1Encodable[]) professionInfos);
    }

    public GeneralName getAdmissionAuthority() {
        return this.admissionAuthority;
    }

    public NamingAuthority getNamingAuthority() {
        return this.namingAuthority;
    }

    public ProfessionInfo[] getProfessionInfos() {
        ProfessionInfo[] infos = new ProfessionInfo[this.professionInfos.size()];
        int count = 0;
        Enumeration e = this.professionInfos.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            infos[count] = ProfessionInfo.getInstance(e.nextElement());
            count = count2;
        }
        return infos;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (this.admissionAuthority != null) {
            vec.add(new DERTaggedObject(true, 0, this.admissionAuthority));
        }
        if (this.namingAuthority != null) {
            vec.add(new DERTaggedObject(true, 1, this.namingAuthority));
        }
        vec.add(this.professionInfos);
        return new DERSequence(vec);
    }
}
