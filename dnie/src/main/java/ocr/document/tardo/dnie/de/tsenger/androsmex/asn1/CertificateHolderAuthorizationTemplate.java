package de.tsenger.androsmex.asn1;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class CertificateHolderAuthorizationTemplate extends ASN1Encodable {
    private DiscretionaryData auth = null;
    private byte role;
    private DERObjectIdentifier terminalType = null;

    public CertificateHolderAuthorizationTemplate(DERObjectIdentifier terminalType, DiscretionaryData disData) {
        this.terminalType = terminalType;
        this.auth = disData;
    }

    public CertificateHolderAuthorizationTemplate(DERSequence chatSeq) throws IOException {
        this.terminalType = (DERObjectIdentifier) chatSeq.getObjectAt(0);
        this.auth = new DiscretionaryData(((DEROctetString) ((DERApplicationSpecific) chatSeq.getObjectAt(1)).getObject(4)).getOctets());
    }

    public DERApplicationSpecific toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.terminalType);
        v.add(this.auth);
        return new DERApplicationSpecific(76, v);
    }

    public byte getRole() {
        this.role = (byte) (this.auth.getData()[0] & 192);
        return this.role;
    }
}
