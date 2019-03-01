package org.spongycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;

public class AuthorityKeyIdentifier extends ASN1Encodable {
    GeneralNames certissuer;
    DERInteger certserno;
    ASN1OctetString keyidentifier;

    public static AuthorityKeyIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthorityKeyIdentifier getInstance(Object obj) {
        if (obj instanceof AuthorityKeyIdentifier) {
            return (AuthorityKeyIdentifier) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AuthorityKeyIdentifier((ASN1Sequence) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AuthorityKeyIdentifier(ASN1Sequence seq) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 0:
                    this.keyidentifier = ASN1OctetString.getInstance(o, false);
                    break;
                case 1:
                    this.certissuer = GeneralNames.getInstance(o, false);
                    break;
                case 2:
                    this.certserno = DERInteger.getInstance(o, false);
                    break;
                default:
                    throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        this.keyidentifier = new DEROctetString(resBuf);
    }

    public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki, GeneralNames name, BigInteger serialNumber) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        this.keyidentifier = new DEROctetString(resBuf);
        this.certissuer = GeneralNames.getInstance(name.toASN1Object());
        this.certserno = new DERInteger(serialNumber);
    }

    public AuthorityKeyIdentifier(GeneralNames name, BigInteger serialNumber) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        this.keyidentifier = null;
        this.certissuer = GeneralNames.getInstance(name.toASN1Object());
        this.certserno = new DERInteger(serialNumber);
    }

    public AuthorityKeyIdentifier(byte[] keyIdentifier) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        this.keyidentifier = new DEROctetString(keyIdentifier);
        this.certissuer = null;
        this.certserno = null;
    }

    public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames name, BigInteger serialNumber) {
        this.keyidentifier = null;
        this.certissuer = null;
        this.certserno = null;
        this.keyidentifier = new DEROctetString(keyIdentifier);
        this.certissuer = GeneralNames.getInstance(name.toASN1Object());
        this.certserno = new DERInteger(serialNumber);
    }

    public byte[] getKeyIdentifier() {
        if (this.keyidentifier != null) {
            return this.keyidentifier.getOctets();
        }
        return null;
    }

    public GeneralNames getAuthorityCertIssuer() {
        return this.certissuer;
    }

    public BigInteger getAuthorityCertSerialNumber() {
        if (this.certserno != null) {
            return this.certserno.getValue();
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.keyidentifier != null) {
            v.add(new DERTaggedObject(false, 0, this.keyidentifier));
        }
        if (this.certissuer != null) {
            v.add(new DERTaggedObject(false, 1, this.certissuer));
        }
        if (this.certserno != null) {
            v.add(new DERTaggedObject(false, 2, this.certserno));
        }
        return new DERSequence(v);
    }

    public String toString() {
        return "AuthorityKeyIdentifier: KeyID(" + this.keyidentifier.getOctets() + ")";
    }
}
