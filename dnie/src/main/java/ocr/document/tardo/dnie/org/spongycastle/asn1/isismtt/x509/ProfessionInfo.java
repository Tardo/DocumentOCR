package org.spongycastle.asn1.isismtt.x509;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x500.DirectoryString;

public class ProfessionInfo extends ASN1Encodable {
    public static final DERObjectIdentifier Notar = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".9");
    public static final DERObjectIdentifier Notariatsverwalter = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".13");
    public static final DERObjectIdentifier Notariatsverwalterin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".12");
    public static final DERObjectIdentifier Notarin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".8");
    public static final DERObjectIdentifier Notarvertreter = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".11");
    public static final DERObjectIdentifier Notarvertreterin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".10");
    public static final DERObjectIdentifier Patentanwalt = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".19");
    public static final DERObjectIdentifier Patentanwltin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".18");
    public static final DERObjectIdentifier Rechtsanwalt = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".2");
    public static final DERObjectIdentifier Rechtsanwltin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".1");
    public static final DERObjectIdentifier Rechtsbeistand = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".3");
    public static final DERObjectIdentifier Steuerberater = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".5");
    public static final DERObjectIdentifier Steuerberaterin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".4");
    public static final DERObjectIdentifier Steuerbevollmchtigte = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".6");
    public static final DERObjectIdentifier Steuerbevollmchtigter = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".7");
    public static final DERObjectIdentifier VereidigteBuchprferin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".16");
    public static final DERObjectIdentifier VereidigterBuchprfer = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".17");
    public static final DERObjectIdentifier Wirtschaftsprfer = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".15");
    public static final DERObjectIdentifier Wirtschaftsprferin = new DERObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".14");
    private ASN1OctetString addProfessionInfo;
    private NamingAuthority namingAuthority;
    private ASN1Sequence professionItems;
    private ASN1Sequence professionOIDs;
    private String registrationNumber;

    public static ProfessionInfo getInstance(Object obj) {
        if (obj == null || (obj instanceof ProfessionInfo)) {
            return (ProfessionInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ProfessionInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private ProfessionInfo(ASN1Sequence seq) {
        if (seq.size() > 5) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        DEREncodable o = (DEREncodable) e.nextElement();
        if (o instanceof ASN1TaggedObject) {
            if (((ASN1TaggedObject) o).getTagNo() != 0) {
                throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject) o).getTagNo());
            }
            this.namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject) o, true);
            o = (DEREncodable) e.nextElement();
        }
        this.professionItems = ASN1Sequence.getInstance(o);
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof ASN1Sequence) {
                this.professionOIDs = ASN1Sequence.getInstance(o);
            } else if (o instanceof DERPrintableString) {
                this.registrationNumber = DERPrintableString.getInstance(o).getString();
            } else if (o instanceof ASN1OctetString) {
                this.addProfessionInfo = ASN1OctetString.getInstance(o);
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
        }
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof DERPrintableString) {
                this.registrationNumber = DERPrintableString.getInstance(o).getString();
            } else if (o instanceof DEROctetString) {
                this.addProfessionInfo = (DEROctetString) o;
            } else {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
        }
        if (e.hasMoreElements()) {
            o = (DEREncodable) e.nextElement();
            if (o instanceof DEROctetString) {
                this.addProfessionInfo = (DEROctetString) o;
                return;
            }
            throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
        }
    }

    public ProfessionInfo(NamingAuthority namingAuthority, DirectoryString[] professionItems, DERObjectIdentifier[] professionOIDs, String registrationNumber, ASN1OctetString addProfessionInfo) {
        int i;
        this.namingAuthority = namingAuthority;
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (i = 0; i != professionItems.length; i++) {
            v.add(professionItems[i]);
        }
        this.professionItems = new DERSequence(v);
        if (professionOIDs != null) {
            v = new ASN1EncodableVector();
            for (i = 0; i != professionOIDs.length; i++) {
                v.add(professionOIDs[i]);
            }
            this.professionOIDs = new DERSequence(v);
        }
        this.registrationNumber = registrationNumber;
        this.addProfessionInfo = addProfessionInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (this.namingAuthority != null) {
            vec.add(new DERTaggedObject(true, 0, this.namingAuthority));
        }
        vec.add(this.professionItems);
        if (this.professionOIDs != null) {
            vec.add(this.professionOIDs);
        }
        if (this.registrationNumber != null) {
            vec.add(new DERPrintableString(this.registrationNumber, true));
        }
        if (this.addProfessionInfo != null) {
            vec.add(this.addProfessionInfo);
        }
        return new DERSequence(vec);
    }

    public ASN1OctetString getAddProfessionInfo() {
        return this.addProfessionInfo;
    }

    public NamingAuthority getNamingAuthority() {
        return this.namingAuthority;
    }

    public DirectoryString[] getProfessionItems() {
        DirectoryString[] items = new DirectoryString[this.professionItems.size()];
        int count = 0;
        Enumeration e = this.professionItems.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            items[count] = DirectoryString.getInstance(e.nextElement());
            count = count2;
        }
        return items;
    }

    public DERObjectIdentifier[] getProfessionOIDs() {
        if (this.professionOIDs == null) {
            return new DERObjectIdentifier[0];
        }
        DERObjectIdentifier[] oids = new DERObjectIdentifier[this.professionOIDs.size()];
        int count = 0;
        Enumeration e = this.professionOIDs.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            oids[count] = DERObjectIdentifier.getInstance(e.nextElement());
            count = count2;
        }
        return oids;
    }

    public String getRegistrationNumber() {
        return this.registrationNumber;
    }
}
