package org.spongycastle.asn1.isismtt.x509;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class DeclarationOfMajority extends ASN1Encodable implements ASN1Choice {
    public static final int dateOfBirth = 2;
    public static final int fullAgeAtCountry = 1;
    public static final int notYoungerThan = 0;
    private ASN1TaggedObject declaration;

    public DeclarationOfMajority(int notYoungerThan) {
        this.declaration = new DERTaggedObject(false, 0, new DERInteger(notYoungerThan));
    }

    public DeclarationOfMajority(boolean fullAge, String country) {
        if (country.length() > 2) {
            throw new IllegalArgumentException("country can only be 2 characters");
        } else if (fullAge) {
            this.declaration = new DERTaggedObject(false, 1, new DERSequence(new DERPrintableString(country, true)));
        } else {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(DERBoolean.FALSE);
            v.add(new DERPrintableString(country, true));
            this.declaration = new DERTaggedObject(false, 1, new DERSequence(v));
        }
    }

    public DeclarationOfMajority(DERGeneralizedTime dateOfBirth) {
        this.declaration = new DERTaggedObject(false, 2, dateOfBirth);
    }

    public static DeclarationOfMajority getInstance(Object obj) {
        if (obj == null || (obj instanceof DeclarationOfMajority)) {
            return (DeclarationOfMajority) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new DeclarationOfMajority((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private DeclarationOfMajority(ASN1TaggedObject o) {
        if (o.getTagNo() > 2) {
            throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
        }
        this.declaration = o;
    }

    public DERObject toASN1Object() {
        return this.declaration;
    }

    public int getType() {
        return this.declaration.getTagNo();
    }

    public int notYoungerThan() {
        if (this.declaration.getTagNo() != 0) {
            return -1;
        }
        return DERInteger.getInstance(this.declaration, false).getValue().intValue();
    }

    public ASN1Sequence fullAgeAtCountry() {
        if (this.declaration.getTagNo() != 1) {
            return null;
        }
        return ASN1Sequence.getInstance(this.declaration, false);
    }

    public DERGeneralizedTime getDateOfBirth() {
        if (this.declaration.getTagNo() != 2) {
            return null;
        }
        return DERGeneralizedTime.getInstance(this.declaration, false);
    }
}
