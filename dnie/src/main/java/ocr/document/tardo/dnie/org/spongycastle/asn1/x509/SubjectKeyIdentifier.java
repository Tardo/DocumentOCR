package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;

public class SubjectKeyIdentifier extends ASN1Encodable {
    private byte[] keyidentifier;

    public static SubjectKeyIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1OctetString.getInstance(obj, explicit));
    }

    public static SubjectKeyIdentifier getInstance(Object obj) {
        if (obj instanceof SubjectKeyIdentifier) {
            return (SubjectKeyIdentifier) obj;
        }
        if (obj instanceof SubjectPublicKeyInfo) {
            return new SubjectKeyIdentifier((SubjectPublicKeyInfo) obj);
        }
        if (obj instanceof ASN1OctetString) {
            return new SubjectKeyIdentifier((ASN1OctetString) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("Invalid SubjectKeyIdentifier: " + obj.getClass().getName());
    }

    public SubjectKeyIdentifier(byte[] keyid) {
        this.keyidentifier = keyid;
    }

    public SubjectKeyIdentifier(ASN1OctetString keyid) {
        this.keyidentifier = keyid.getOctets();
    }

    public SubjectKeyIdentifier(SubjectPublicKeyInfo spki) {
        this.keyidentifier = getDigest(spki);
    }

    public byte[] getKeyIdentifier() {
        return this.keyidentifier;
    }

    public DERObject toASN1Object() {
        return new DEROctetString(this.keyidentifier);
    }

    public static SubjectKeyIdentifier createSHA1KeyIdentifier(SubjectPublicKeyInfo keyInfo) {
        return new SubjectKeyIdentifier(keyInfo);
    }

    public static SubjectKeyIdentifier createTruncatedSHA1KeyIdentifier(SubjectPublicKeyInfo keyInfo) {
        byte[] dig = getDigest(keyInfo);
        byte[] id = new byte[8];
        System.arraycopy(dig, dig.length - 8, id, 0, id.length);
        id[0] = (byte) (id[0] & 15);
        id[0] = (byte) (id[0] | 64);
        return new SubjectKeyIdentifier(id);
    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki) {
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
