package de.tsenger.androsmex.asn1;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;

public class PrivilegedTerminalInfo extends ASN1Encodable {
    private DERObjectIdentifier protocol = null;
    private SecurityInfos secinfos = null;

    public PrivilegedTerminalInfo(DERSequence seq) throws IOException {
        this.protocol = (DERObjectIdentifier) seq.getObjectAt(0);
        DERSet derSet = (DERSet) seq.getObjectAt(1);
        SecurityInfos si = new SecurityInfos();
        si.decode(derSet.getEncoded());
        this.secinfos = si;
    }

    public String getProtocolOID() {
        return this.protocol.getId();
    }

    public SecurityInfos getSecurityInfos() {
        return this.secinfos;
    }

    public String toString() {
        return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID() + "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.protocol);
        v.add(this.secinfos);
        return new DERSequence(v);
    }
}
