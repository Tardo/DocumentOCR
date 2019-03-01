package org.spongycastle.ocsp;

import java.security.MessageDigest;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.ocsp.ResponderID;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;

public class RespID {
    ResponderID id;

    public RespID(ResponderID id) {
        this.id = id;
    }

    public RespID(X500Principal name) {
        this.id = new ResponderID(X500Name.getInstance(name.getEncoded()));
    }

    public RespID(PublicKey key) throws OCSPException {
        try {
            MessageDigest digest = OCSPUtil.createDigestInstance("SHA1", null);
            digest.update(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(key.getEncoded()).readObject()).getPublicKeyData().getBytes());
            this.id = new ResponderID(new DEROctetString(digest.digest()));
        } catch (Exception e) {
            throw new OCSPException("problem creating ID: " + e, e);
        }
    }

    public ResponderID toASN1Object() {
        return this.id;
    }

    public boolean equals(Object o) {
        if (!(o instanceof RespID)) {
            return false;
        }
        return this.id.equals(((RespID) o).id);
    }

    public int hashCode() {
        return this.id.hashCode();
    }
}
