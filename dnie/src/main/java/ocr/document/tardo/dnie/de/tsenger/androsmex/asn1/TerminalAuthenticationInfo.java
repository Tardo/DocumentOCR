package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class TerminalAuthenticationInfo extends ASN1Encodable {
    private DERSequence fileID = null;
    private DERObjectIdentifier protocol = null;
    private DERInteger version = null;

    public TerminalAuthenticationInfo(DERSequence seq) {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        this.version = (DERInteger) seq.getObjectAt(1);
        if (seq.size() > 2) {
            this.fileID = (DERSequence) seq.getObjectAt(2);
        }
        if (this.version.getValue().intValue() == 2 && this.fileID != null) {
            throw new IllegalArgumentException("FileID MUST NOT be used for version 2!");
        }
    }

    public String getProtocolOID() {
        return this.protocol.toString();
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public FileID getEFCVCA() {
        if (this.fileID == null) {
            return null;
        }
        return new FileID(this.fileID);
    }

    public String toString() {
        return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID() + "\n\tVersion: " + getVersion() + "\n\tEF.CVCA: " + getEFCVCA() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.version);
        if (this.fileID != null) {
            v.add(this.fileID);
        }
        return new DERSequence(v);
    }
}
