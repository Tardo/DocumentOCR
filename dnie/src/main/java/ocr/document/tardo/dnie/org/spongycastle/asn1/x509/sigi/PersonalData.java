package org.spongycastle.asn1.x509.sigi;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x500.DirectoryString;

public class PersonalData extends ASN1Encodable {
    private DERGeneralizedTime dateOfBirth;
    private String gender;
    private BigInteger nameDistinguisher;
    private NameOrPseudonym nameOrPseudonym;
    private DirectoryString placeOfBirth;
    private DirectoryString postalAddress;

    public static PersonalData getInstance(Object obj) {
        if (obj == null || (obj instanceof PersonalData)) {
            return (PersonalData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PersonalData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private PersonalData(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.nameOrPseudonym = NameOrPseudonym.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 0:
                    this.nameDistinguisher = DERInteger.getInstance(o, false).getValue();
                    break;
                case 1:
                    this.dateOfBirth = DERGeneralizedTime.getInstance(o, false);
                    break;
                case 2:
                    this.placeOfBirth = DirectoryString.getInstance(o, true);
                    break;
                case 3:
                    this.gender = DERPrintableString.getInstance(o, false).getString();
                    break;
                case 4:
                    this.postalAddress = DirectoryString.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    public PersonalData(NameOrPseudonym nameOrPseudonym, BigInteger nameDistinguisher, DERGeneralizedTime dateOfBirth, DirectoryString placeOfBirth, String gender, DirectoryString postalAddress) {
        this.nameOrPseudonym = nameOrPseudonym;
        this.dateOfBirth = dateOfBirth;
        this.gender = gender;
        this.nameDistinguisher = nameDistinguisher;
        this.postalAddress = postalAddress;
        this.placeOfBirth = placeOfBirth;
    }

    public NameOrPseudonym getNameOrPseudonym() {
        return this.nameOrPseudonym;
    }

    public BigInteger getNameDistinguisher() {
        return this.nameDistinguisher;
    }

    public DERGeneralizedTime getDateOfBirth() {
        return this.dateOfBirth;
    }

    public DirectoryString getPlaceOfBirth() {
        return this.placeOfBirth;
    }

    public String getGender() {
        return this.gender;
    }

    public DirectoryString getPostalAddress() {
        return this.postalAddress;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(this.nameOrPseudonym);
        if (this.nameDistinguisher != null) {
            vec.add(new DERTaggedObject(false, 0, new DERInteger(this.nameDistinguisher)));
        }
        if (this.dateOfBirth != null) {
            vec.add(new DERTaggedObject(false, 1, this.dateOfBirth));
        }
        if (this.placeOfBirth != null) {
            vec.add(new DERTaggedObject(true, 2, this.placeOfBirth));
        }
        if (this.gender != null) {
            vec.add(new DERTaggedObject(false, 3, new DERPrintableString(this.gender, true)));
        }
        if (this.postalAddress != null) {
            vec.add(new DERTaggedObject(true, 4, this.postalAddress));
        }
        return new DERSequence(vec);
    }
}
