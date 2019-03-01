package org.spongycastle.ocsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.ocsp.CertID;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.jce.PrincipalUtil;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class CertificateID {
    public static final String HASH_SHA1 = "1.3.14.3.2.26";
    private final CertID id;

    public CertificateID(CertID id) {
        if (id == null) {
            throw new IllegalArgumentException("'id' cannot be null");
        }
        this.id = id;
    }

    public CertificateID(String hashAlgorithm, X509Certificate issuerCert, BigInteger number, String provider) throws OCSPException {
        this.id = createCertID(new AlgorithmIdentifier(new DERObjectIdentifier(hashAlgorithm), DERNull.INSTANCE), issuerCert, new DERInteger(number), provider);
    }

    public CertificateID(String hashAlgorithm, X509Certificate issuerCert, BigInteger number) throws OCSPException {
        this(hashAlgorithm, issuerCert, number, BouncyCastleProvider.PROVIDER_NAME);
    }

    public String getHashAlgOID() {
        return this.id.getHashAlgorithm().getObjectId().getId();
    }

    public byte[] getIssuerNameHash() {
        return this.id.getIssuerNameHash().getOctets();
    }

    public byte[] getIssuerKeyHash() {
        return this.id.getIssuerKeyHash().getOctets();
    }

    public BigInteger getSerialNumber() {
        return this.id.getSerialNumber().getValue();
    }

    public boolean matchesIssuer(X509Certificate issuerCert, String provider) throws OCSPException {
        return createCertID(this.id.getHashAlgorithm(), issuerCert, this.id.getSerialNumber(), provider).equals(this.id);
    }

    public CertID toASN1Object() {
        return this.id;
    }

    public boolean equals(Object o) {
        if (!(o instanceof CertificateID)) {
            return false;
        }
        return this.id.getDERObject().equals(((CertificateID) o).id.getDERObject());
    }

    public int hashCode() {
        return this.id.getDERObject().hashCode();
    }

    public static CertificateID deriveCertificateID(CertificateID original, BigInteger newSerialNumber) {
        return new CertificateID(new CertID(original.id.getHashAlgorithm(), original.id.getIssuerNameHash(), original.id.getIssuerKeyHash(), new DERInteger(newSerialNumber)));
    }

    private static CertID createCertID(AlgorithmIdentifier hashAlg, X509Certificate issuerCert, DERInteger serialNumber, String provider) throws OCSPException {
        try {
            MessageDigest digest = OCSPUtil.createDigestInstance(hashAlg.getAlgorithm().getId(), provider);
            digest.update(PrincipalUtil.getSubjectX509Principal(issuerCert).getEncoded());
            ASN1OctetString issuerNameHash = new DEROctetString(digest.digest());
            digest.update(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(issuerCert.getPublicKey().getEncoded()).readObject()).getPublicKeyData().getBytes());
            return new CertID(hashAlg, issuerNameHash, new DEROctetString(digest.digest()), serialNumber);
        } catch (Exception e) {
            throw new OCSPException("problem creating ID: " + e, e);
        }
    }
}
