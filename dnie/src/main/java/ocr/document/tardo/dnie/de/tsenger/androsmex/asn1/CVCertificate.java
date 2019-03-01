package de.tsenger.androsmex.asn1;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1StreamParser;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class CVCertificate extends ASN1Encodable {
    private CVCertBody certBody = null;
    private CVCertSignature certSignature = null;

    public CVCertificate(byte[] in) throws IllegalArgumentException, IOException {
        DERApplicationSpecific cvcert = (DERApplicationSpecific) new ASN1StreamParser(in).readObject();
        if (cvcert.getApplicationTag() != 33) {
            throw new IllegalArgumentException("Can't find a CV Certificate");
        }
        DERSequence derCert = (DERSequence) cvcert.getObject(16);
        DERApplicationSpecific body = (DERApplicationSpecific) derCert.getObjectAt(0);
        if (body.getApplicationTag() != 78) {
            throw new IllegalArgumentException("Can't find a Body in the CV Certificate");
        }
        this.certBody = new CVCertBody(body);
        DERApplicationSpecific signature = (DERApplicationSpecific) derCert.getObjectAt(1);
        if (signature.getApplicationTag() != 55) {
            throw new IllegalArgumentException("Can't find a Signature in the CV Certificate");
        }
        this.certSignature = new CVCertSignature(signature.getContents());
    }

    public CVCertSignature getSignature() {
        return this.certSignature;
    }

    public CVCertBody getBody() {
        return this.certBody;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certBody);
        v.add(this.certSignature);
        return new DERApplicationSpecific(33, v);
    }
}
