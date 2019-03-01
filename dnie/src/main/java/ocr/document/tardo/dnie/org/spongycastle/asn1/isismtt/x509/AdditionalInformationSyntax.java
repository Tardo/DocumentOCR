package org.spongycastle.asn1.isismtt.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x500.DirectoryString;

public class AdditionalInformationSyntax extends ASN1Encodable {
    private DirectoryString information;

    public static AdditionalInformationSyntax getInstance(Object obj) {
        if (obj instanceof AdditionalInformationSyntax) {
            return (AdditionalInformationSyntax) obj;
        }
        if (obj instanceof ASN1String) {
            return new AdditionalInformationSyntax(DirectoryString.getInstance(obj));
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private AdditionalInformationSyntax(DirectoryString information) {
        this.information = information;
    }

    public AdditionalInformationSyntax(String information) {
        this(new DirectoryString(information));
    }

    public DirectoryString getInformation() {
        return this.information;
    }

    public DERObject toASN1Object() {
        return this.information.toASN1Object();
    }
}
