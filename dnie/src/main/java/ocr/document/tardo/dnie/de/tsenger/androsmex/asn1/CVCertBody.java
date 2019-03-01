package de.tsenger.androsmex.asn1;

import de.tsenger.androsmex.tools.Converter;
import java.io.IOException;
import java.util.Date;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class CVCertBody extends ASN1Encodable {
    private DERIA5String authorityReference = null;
    private CertificateHolderAuthorizationTemplate chat = null;
    private DERIA5String chr = null;
    private DERApplicationSpecific cvcbody = null;
    private DEROctetString effectiveDate = null;
    private DEROctetString expirationDate = null;
    private DERSequence extensions = null;
    private DERInteger profileIdentifier = null;
    private AmPublicKey publicKey = null;

    public CVCertBody(DERSequence derSeq) {
    }

    public CVCertBody(DERApplicationSpecific derApp) throws IllegalArgumentException, IOException {
        if (derApp.getApplicationTag() != 78) {
            throw new IllegalArgumentException("contains no Certifcate Body with tag 0x7F4E");
        }
        this.cvcbody = derApp;
        DERSequence bodySeq = (DERSequence) this.cvcbody.getObject(16);
        this.profileIdentifier = (DERInteger) ((DERApplicationSpecific) bodySeq.getObjectAt(0)).getObject(2);
        this.authorityReference = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(1)).getObject(22);
        DERSequence pkSeq = (DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(2)).getObject(16);
        DERObjectIdentifier pkOid = (DERObjectIdentifier) pkSeq.getObjectAt(0);
        if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.2")) {
            this.publicKey = new AmECPublicKey(pkSeq);
        } else if (pkOid.toString().startsWith("0.4.0.127.0.7.2.2.2.1")) {
            this.publicKey = new AmRSAPublicKey(pkSeq);
        }
        this.chr = (DERIA5String) ((DERApplicationSpecific) bodySeq.getObjectAt(3)).getObject(22);
        this.chat = new CertificateHolderAuthorizationTemplate((DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(4)).getObject(16));
        this.effectiveDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(5)).getObject(4);
        this.expirationDate = (DEROctetString) ((DERApplicationSpecific) bodySeq.getObjectAt(6)).getObject(4);
        if (bodySeq.size() > 7) {
            this.extensions = (DERSequence) ((DERApplicationSpecific) bodySeq.getObjectAt(7)).getObject(16);
        }
    }

    public byte[] getDEREncoded() {
        return this.cvcbody.getDEREncoded();
    }

    public int getProfileIdentifier() {
        return this.profileIdentifier.getPositiveValue().intValue();
    }

    public String getCAR() {
        return this.authorityReference.getString();
    }

    public AmPublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getCHR() {
        return this.chr.getString();
    }

    public CertificateHolderAuthorizationTemplate getCHAT() {
        return this.chat;
    }

    public Date getEffectiveDateDate() {
        return Converter.BCDtoDate(this.effectiveDate.getOctets());
    }

    public Date getExpirationDate() {
        return Converter.BCDtoDate(this.expirationDate.getOctets());
    }

    public String toString() {
        return new String("Certificate Body\n\tProfile Identifier: " + this.profileIdentifier + "\n" + "\tAuthority Reference: " + this.authorityReference.getString() + "\n" + "\tPublic Key: " + this.publicKey.getOID() + "\n" + "\tHolder Reference: " + this.chr.getString() + "\n" + "\tCHAT (Role): " + this.chat.getRole() + "\n" + "\teffective Date: " + getEffectiveDateDate() + "\n" + "\texpiration Date: " + getExpirationDate());
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        try {
            v.add(new DERApplicationSpecific(41, this.profileIdentifier));
            v.add(new DERApplicationSpecific(2, this.authorityReference));
            v.add(this.publicKey);
            v.add(new DERApplicationSpecific(32, this.chr));
            v.add(this.chat);
            v.add(new DERApplicationSpecific(37, this.effectiveDate));
            v.add(new DERApplicationSpecific(36, this.expirationDate));
            if (this.extensions != null) {
                v.add(new DERApplicationSpecific(5, this.extensions));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new DERApplicationSpecific(78, v);
    }
}
