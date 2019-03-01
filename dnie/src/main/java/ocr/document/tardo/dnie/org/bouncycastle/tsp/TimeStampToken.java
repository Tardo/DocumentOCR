package org.bouncycastle.tsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

public class TimeStampToken {
    CertID certID;
    Date genTime;
    CMSSignedData tsToken;
    SignerInformation tsaSignerInfo;
    TimeStampTokenInfo tstInfo;

    private class CertID {
        private ESSCertID certID;
        private ESSCertIDv2 certIDv2;

        CertID(ESSCertID eSSCertID) {
            this.certID = eSSCertID;
            this.certIDv2 = null;
        }

        CertID(ESSCertIDv2 eSSCertIDv2) {
            this.certIDv2 = eSSCertIDv2;
            this.certID = null;
        }

        public byte[] getCertHash() {
            return this.certID != null ? this.certID.getCertHash() : this.certIDv2.getCertHash();
        }

        public AlgorithmIdentifier getHashAlgorithm() {
            return this.certID != null ? new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1) : this.certIDv2.getHashAlgorithm();
        }

        public String getHashAlgorithmName() {
            return this.certID != null ? "SHA-1" : NISTObjectIdentifiers.id_sha256.equals(this.certIDv2.getHashAlgorithm().getAlgorithm()) ? "SHA-256" : this.certIDv2.getHashAlgorithm().getAlgorithm().getId();
        }

        public IssuerSerial getIssuerSerial() {
            return this.certID != null ? this.certID.getIssuerSerial() : this.certIDv2.getIssuerSerial();
        }
    }

    public TimeStampToken(ContentInfo contentInfo) throws TSPException, IOException {
        this(getSignedData(contentInfo));
    }

    public TimeStampToken(CMSSignedData cMSSignedData) throws TSPException, IOException {
        this.tsToken = cMSSignedData;
        if (this.tsToken.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.id_ct_TSTInfo.getId())) {
            Collection signers = this.tsToken.getSignerInfos().getSigners();
            if (signers.size() != 1) {
                throw new IllegalArgumentException("Time-stamp token signed by " + signers.size() + " signers, but it must contain just the TSA signature.");
            }
            this.tsaSignerInfo = (SignerInformation) signers.iterator().next();
            try {
                CMSProcessable signedContent = this.tsToken.getSignedContent();
                OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                signedContent.write(byteArrayOutputStream);
                this.tstInfo = new TimeStampTokenInfo(TSTInfo.getInstance(new ASN1InputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray())).readObject()));
                Attribute attribute = this.tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate);
                if (attribute != null) {
                    this.certID = new CertID(ESSCertID.getInstance(SigningCertificate.getInstance(attribute.getAttrValues().getObjectAt(0)).getCerts()[0]));
                    return;
                }
                attribute = this.tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                if (attribute == null) {
                    throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
                }
                this.certID = new CertID(ESSCertIDv2.getInstance(SigningCertificateV2.getInstance(attribute.getAttrValues().getObjectAt(0)).getCerts()[0]));
                return;
            } catch (CMSException e) {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
        }
        throw new TSPValidationException("ContentInfo object not for a time stamp.");
    }

    private static CMSSignedData getSignedData(ContentInfo contentInfo) throws TSPException {
        try {
            return new CMSSignedData(contentInfo);
        } catch (CMSException e) {
            throw new TSPException("TSP parsing error: " + e.getMessage(), e.getCause());
        }
    }

    public Store getAttributeCertificates() {
        return this.tsToken.getAttributeCertificates();
    }

    public Store getCRLs() {
        return this.tsToken.getCRLs();
    }

    public Store getCertificates() {
        return this.tsToken.getCertificates();
    }

    public CertStore getCertificatesAndCRLs(String str, String str2) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        return this.tsToken.getCertificatesAndCRLs(str, str2);
    }

    public byte[] getEncoded() throws IOException {
        return this.tsToken.getEncoded();
    }

    public SignerId getSID() {
        return this.tsaSignerInfo.getSID();
    }

    public AttributeTable getSignedAttributes() {
        return this.tsaSignerInfo.getSignedAttributes();
    }

    public TimeStampTokenInfo getTimeStampInfo() {
        return this.tstInfo;
    }

    public AttributeTable getUnsignedAttributes() {
        return this.tsaSignerInfo.getUnsignedAttributes();
    }

    public boolean isSignatureValid(SignerInformationVerifier signerInformationVerifier) throws TSPException {
        try {
            return this.tsaSignerInfo.verify(signerInformationVerifier);
        } catch (Throwable e) {
            if (e.getUnderlyingException() != null) {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
            throw new TSPException("CMS exception: " + e, e);
        }
    }

    public CMSSignedData toCMSSignedData() {
        return this.tsToken;
    }

    public void validate(X509Certificate x509Certificate, String str) throws TSPException, TSPValidationException, CertificateExpiredException, CertificateNotYetValidException, NoSuchProviderException {
        Object obj = null;
        try {
            if (Arrays.constantTimeAreEqual(this.certID.getCertHash(), MessageDigest.getInstance(this.certID.getHashAlgorithmName()).digest(x509Certificate.getEncoded()))) {
                if (this.certID.getIssuerSerial() != null) {
                    if (this.certID.getIssuerSerial().getSerial().getValue().equals(x509Certificate.getSerialNumber())) {
                        GeneralName[] names = this.certID.getIssuerSerial().getIssuer().getNames();
                        X509Principal issuerX509Principal = PrincipalUtil.getIssuerX509Principal(x509Certificate);
                        int i = 0;
                        while (i != names.length) {
                            if (names[i].getTagNo() == 4 && new X509Principal(X509Name.getInstance(names[i].getName())).equals(issuerX509Principal)) {
                                obj = 1;
                                break;
                            }
                            i++;
                        }
                        if (obj == null) {
                            throw new TSPValidationException("certificate name does not match certID for signature. ");
                        }
                    }
                    throw new TSPValidationException("certificate serial number does not match certID for signature.");
                }
                TSPUtil.validateCertificate(x509Certificate);
                x509Certificate.checkValidity(this.tstInfo.getGenTime());
                if (!this.tsaSignerInfo.verify(x509Certificate, str)) {
                    throw new TSPValidationException("signature not created by certificate.");
                }
                return;
            }
            throw new TSPValidationException("certificate hash does not match certID hash.");
        } catch (Throwable e) {
            if (e.getUnderlyingException() != null) {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
            throw new TSPException("CMS exception: " + e, e);
        } catch (Throwable e2) {
            throw new TSPException("cannot find algorithm: " + e2, e2);
        } catch (Throwable e22) {
            throw new TSPException("problem processing certificate: " + e22, e22);
        }
    }

    public void validate(SignerInformationVerifier signerInformationVerifier) throws TSPException, TSPValidationException {
        Object obj = null;
        if (signerInformationVerifier.hasAssociatedCertificate()) {
            try {
                X509CertificateHolder associatedCertificate = signerInformationVerifier.getAssociatedCertificate();
                DigestCalculator digestCalculator = signerInformationVerifier.getDigestCalculator(this.certID.getHashAlgorithm());
                OutputStream outputStream = digestCalculator.getOutputStream();
                outputStream.write(associatedCertificate.getEncoded());
                outputStream.close();
                if (Arrays.constantTimeAreEqual(this.certID.getCertHash(), digestCalculator.getDigest())) {
                    if (this.certID.getIssuerSerial() != null) {
                        IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(associatedCertificate.toASN1Structure());
                        if (this.certID.getIssuerSerial().getSerial().equals(issuerAndSerialNumber.getSerialNumber())) {
                            GeneralName[] names = this.certID.getIssuerSerial().getIssuer().getNames();
                            int i = 0;
                            while (i != names.length) {
                                if (names[i].getTagNo() == 4 && X500Name.getInstance(names[i].getName()).equals(X500Name.getInstance(issuerAndSerialNumber.getName()))) {
                                    obj = 1;
                                    break;
                                }
                                i++;
                            }
                            if (obj == null) {
                                throw new TSPValidationException("certificate name does not match certID for signature. ");
                            }
                        }
                        throw new TSPValidationException("certificate serial number does not match certID for signature.");
                    }
                    TSPUtil.validateCertificate(associatedCertificate);
                    if (!associatedCertificate.isValidOn(this.tstInfo.getGenTime())) {
                        throw new TSPValidationException("certificate not valid when time stamp created.");
                    } else if (!this.tsaSignerInfo.verify(signerInformationVerifier)) {
                        throw new TSPValidationException("signature not created by certificate.");
                    } else {
                        return;
                    }
                }
                throw new TSPValidationException("certificate hash does not match certID hash.");
            } catch (Throwable e) {
                if (e.getUnderlyingException() != null) {
                    throw new TSPException(e.getMessage(), e.getUnderlyingException());
                }
                throw new TSPException("CMS exception: " + e, e);
            } catch (Throwable e2) {
                throw new TSPException("problem processing certificate: " + e2, e2);
            } catch (Throwable e22) {
                throw new TSPException("unable to create digest: " + e22.getMessage(), e22);
            }
        }
        throw new IllegalArgumentException("verifier provider needs an associated certificate");
    }
}
