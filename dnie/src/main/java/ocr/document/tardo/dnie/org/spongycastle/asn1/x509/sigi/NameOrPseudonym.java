package org.spongycastle.asn1.x509.sigi;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x500.DirectoryString;

public class NameOrPseudonym extends ASN1Encodable implements ASN1Choice {
    private ASN1Sequence givenName;
    private DirectoryString pseudonym;
    private DirectoryString surname;

    public static NameOrPseudonym getInstance(Object obj) {
        if (obj == null || (obj instanceof NameOrPseudonym)) {
            return (NameOrPseudonym) obj;
        }
        if (obj instanceof ASN1String) {
            return new NameOrPseudonym(DirectoryString.getInstance(obj));
        }
        if (obj instanceof ASN1Sequence) {
            return new NameOrPseudonym((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public NameOrPseudonym(DirectoryString pseudonym) {
        this.pseudonym = pseudonym;
    }

    private NameOrPseudonym(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        } else if (seq.getObjectAt(0) instanceof ASN1String) {
            this.surname = DirectoryString.getInstance(seq.getObjectAt(0));
            this.givenName = ASN1Sequence.getInstance(seq.getObjectAt(1));
        } else {
            throw new IllegalArgumentException("Bad object encountered: " + seq.getObjectAt(0).getClass());
        }
    }

    public NameOrPseudonym(String pseudonym) {
        this(new DirectoryString(pseudonym));
    }

    public NameOrPseudonym(DirectoryString surname, ASN1Sequence givenName) {
        this.surname = surname;
        this.givenName = givenName;
    }

    public DirectoryString getPseudonym() {
        return this.pseudonym;
    }

    public DirectoryString getSurname() {
        return this.surname;
    }

    public DirectoryString[] getGivenName() {
        DirectoryString[] items = new DirectoryString[this.givenName.size()];
        int count = 0;
        Enumeration e = this.givenName.getObjects();
        while (e.hasMoreElements()) {
            int count2 = count + 1;
            items[count] = DirectoryString.getInstance(e.nextElement());
            count = count2;
        }
        return items;
    }

    public DERObject toASN1Object() {
        if (this.pseudonym != null) {
            return this.pseudonym.toASN1Object();
        }
        ASN1EncodableVector vec1 = new ASN1EncodableVector();
        vec1.add(this.surname);
        vec1.add(this.givenName);
        return new DERSequence(vec1);
    }
}
