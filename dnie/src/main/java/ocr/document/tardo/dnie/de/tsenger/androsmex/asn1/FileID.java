package de.tsenger.androsmex.asn1;

import de.tsenger.androsmex.tools.HexString;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class FileID extends ASN1Encodable {
    private DEROctetString fid = null;
    private DEROctetString sfid = null;

    public FileID(DERSequence seq) {
        this.fid = (DEROctetString) seq.getObjectAt(0);
        if (seq.size() > 1) {
            this.sfid = (DEROctetString) seq.getObjectAt(1);
        }
    }

    public byte[] getFID() {
        return this.fid.getOctets();
    }

    public byte getSFID() {
        if (this.sfid != null) {
            return this.sfid.getOctets()[0];
        }
        return (byte) -1;
    }

    public String toString() {
        return "FileID \n\tFID: " + HexString.bufferToHex(getFID()) + "\n\tSFID: " + getSFID() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.fid);
        if (this.sfid != null) {
            v.add(this.sfid);
        }
        return new DERSequence(v);
    }
}
