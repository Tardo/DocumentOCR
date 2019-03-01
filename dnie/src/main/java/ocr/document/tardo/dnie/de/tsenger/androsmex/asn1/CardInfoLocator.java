package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class CardInfoLocator extends ASN1Encodable {
    private DERSequence fileID = null;
    private DERObjectIdentifier protocol = null;
    private DERIA5String url = null;

    public CardInfoLocator(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.url = (DERIA5String) seq.getObjectAt(1);
        if (seq.size() > 2) {
            this.fileID = (DERSequence) seq.getObjectAt(2);
        }
    }

    public DERObjectIdentifier getProtocol() {
        return this.protocol;
    }

    public String getUrl() {
        return this.url.getString();
    }

    public FileID getFileID() {
        if (this.fileID == null) {
            return null;
        }
        return new FileID(this.fileID);
    }

    public String toString() {
        return "CardInfoLocator \n\tOID: " + getProtocol() + "\n\tURL: " + getUrl() + "\n\t" + getFileID() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.url);
        if (this.fileID != null) {
            v.add(this.fileID);
        }
        return new DERSequence(v);
    }
}
