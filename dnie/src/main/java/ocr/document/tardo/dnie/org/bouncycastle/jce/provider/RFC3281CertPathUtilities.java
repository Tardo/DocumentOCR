package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.TargetInformation;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.PKIXAttrCertChecker;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CertStoreSelector;

class RFC3281CertPathUtilities {
    private static final String AUTHORITY_INFO_ACCESS = X509Extensions.AuthorityInfoAccess.getId();
    private static final String CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
    private static final String NO_REV_AVAIL = X509Extensions.NoRevAvail.getId();
    private static final String TARGET_INFORMATION = X509Extensions.TargetInformation.getId();

    RFC3281CertPathUtilities() {
    }

    protected static void additionalChecks(X509AttributeCertificate x509AttributeCertificate, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        for (String str : extendedPKIXParameters.getProhibitedACAttributes()) {
            if (x509AttributeCertificate.getAttributes(str) != null) {
                throw new CertPathValidatorException("Attribute certificate contains prohibited attribute: " + str + ".");
            }
        }
        for (String str2 : extendedPKIXParameters.getNecessaryACAttributes()) {
            if (x509AttributeCertificate.getAttributes(str2) == null) {
                throw new CertPathValidatorException("Attribute certificate does not contain necessary attribute: " + str2 + ".");
            }
        }
    }

    private static void checkCRL(DistributionPoint distributionPoint, X509AttributeCertificate x509AttributeCertificate, ExtendedPKIXParameters extendedPKIXParameters, Date date, X509Certificate x509Certificate, CertStatus certStatus, ReasonsMask reasonsMask, List list) throws AnnotatedException {
        if (x509AttributeCertificate.getExtensionValue(X509Extensions.NoRevAvail.getId()) == null) {
            Date date2 = new Date(System.currentTimeMillis());
            if (date.getTime() > date2.getTime()) {
                throw new AnnotatedException("Validation time is in future.");
            }
            Iterator it = CertPathValidatorUtilities.getCompleteCRLs(distributionPoint, x509AttributeCertificate, date2, extendedPKIXParameters).iterator();
            AnnotatedException annotatedException = null;
            Object obj = null;
            while (it.hasNext() && certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                try {
                    X509CRL x509crl = (X509CRL) it.next();
                    ReasonsMask processCRLD = RFC3280CertPathUtilities.processCRLD(x509crl, distributionPoint);
                    if (processCRLD.hasNewReasons(reasonsMask)) {
                        PublicKey processCRLG = RFC3280CertPathUtilities.processCRLG(x509crl, RFC3280CertPathUtilities.processCRLF(x509crl, x509AttributeCertificate, null, null, extendedPKIXParameters, list));
                        X509CRL x509crl2 = null;
                        if (extendedPKIXParameters.isUseDeltasEnabled()) {
                            x509crl2 = RFC3280CertPathUtilities.processCRLH(CertPathValidatorUtilities.getDeltaCRLs(date2, extendedPKIXParameters, x509crl), processCRLG);
                        }
                        if (extendedPKIXParameters.getValidityModel() == 1 || x509AttributeCertificate.getNotAfter().getTime() >= x509crl.getThisUpdate().getTime()) {
                            RFC3280CertPathUtilities.processCRLB1(distributionPoint, x509AttributeCertificate, x509crl);
                            RFC3280CertPathUtilities.processCRLB2(distributionPoint, x509AttributeCertificate, x509crl);
                            RFC3280CertPathUtilities.processCRLC(x509crl2, x509crl, extendedPKIXParameters);
                            RFC3280CertPathUtilities.processCRLI(date, x509crl2, x509AttributeCertificate, certStatus, extendedPKIXParameters);
                            RFC3280CertPathUtilities.processCRLJ(date, x509crl, x509AttributeCertificate, certStatus);
                            if (certStatus.getCertStatus() == 8) {
                                certStatus.setCertStatus(11);
                            }
                            reasonsMask.addReasons(processCRLD);
                            obj = 1;
                        } else {
                            throw new AnnotatedException("No valid CRL for current time found.");
                        }
                    }
                    continue;
                } catch (AnnotatedException e) {
                    annotatedException = e;
                }
            }
            if (obj == null) {
                throw annotatedException;
            }
        }
    }

    protected static void checkCRLs(X509AttributeCertificate x509AttributeCertificate, ExtendedPKIXParameters extendedPKIXParameters, X509Certificate x509Certificate, Date date, List list) throws CertPathValidatorException {
        if (!extendedPKIXParameters.isRevocationEnabled()) {
            return;
        }
        if (x509AttributeCertificate.getExtensionValue(NO_REV_AVAIL) == null) {
            try {
                CRLDistPoint instance = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(x509AttributeCertificate, CRL_DISTRIBUTION_POINTS));
                try {
                    Object obj;
                    CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(instance, extendedPKIXParameters);
                    CertStatus certStatus = new CertStatus();
                    ReasonsMask reasonsMask = new ReasonsMask();
                    Throwable th = null;
                    if (instance != null) {
                        try {
                            DistributionPoint[] distributionPoints = instance.getDistributionPoints();
                            int i = 0;
                            obj = null;
                            while (i < distributionPoints.length && certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                                try {
                                    checkCRL(distributionPoints[i], x509AttributeCertificate, (ExtendedPKIXParameters) extendedPKIXParameters.clone(), date, x509Certificate, certStatus, reasonsMask, list);
                                    obj = 1;
                                    i++;
                                } catch (Throwable e) {
                                    th = new AnnotatedException("No valid CRL for distribution point found.", e);
                                }
                            }
                        } catch (Throwable e2) {
                            throw new ExtCertPathValidatorException("Distribution points could not be read.", e2);
                        }
                    }
                    obj = null;
                    if (certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                        try {
                            checkCRL(new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(4, new ASN1InputStream(((X500Principal) x509AttributeCertificate.getIssuer().getPrincipals()[0]).getEncoded()).readObject()))), null, null), x509AttributeCertificate, (ExtendedPKIXParameters) extendedPKIXParameters.clone(), date, x509Certificate, certStatus, reasonsMask, list);
                            obj = 1;
                        } catch (Throwable e22) {
                            throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", e22);
                        } catch (Throwable e222) {
                            th = new AnnotatedException("No valid CRL for distribution point found.", e222);
                        }
                    }
                    if (obj == null) {
                        throw new ExtCertPathValidatorException("No valid CRL found.", th);
                    } else if (certStatus.getCertStatus() != 11) {
                        throw new CertPathValidatorException(("Attribute certificate revocation after " + certStatus.getRevocationDate()) + ", reason: " + RFC3280CertPathUtilities.crlReasons[certStatus.getCertStatus()]);
                    } else {
                        if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == 11) {
                            certStatus.setCertStatus(12);
                        }
                        if (certStatus.getCertStatus() == 12) {
                            throw new CertPathValidatorException("Attribute certificate status could not be determined.");
                        }
                    }
                } catch (Throwable e2222) {
                    throw new CertPathValidatorException("No additional CRL locations could be decoded from CRL distribution point extension.", e2222);
                }
            } catch (Throwable e22222) {
                throw new CertPathValidatorException("CRL distribution point extension could not be read.", e22222);
            }
        } else if (x509AttributeCertificate.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null || x509AttributeCertificate.getExtensionValue(AUTHORITY_INFO_ACCESS) != null) {
            throw new CertPathValidatorException("No rev avail extension is set, but also an AC revocation pointer.");
        }
    }

    protected static CertPath processAttrCert1(X509AttributeCertificate x509AttributeCertificate, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        CertPathBuilderResult certPathBuilderResult = null;
        int i = 0;
        Set<X509Certificate> hashSet = new HashSet();
        if (x509AttributeCertificate.getHolder().getIssuer() != null) {
            X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector();
            x509CertStoreSelector.setSerialNumber(x509AttributeCertificate.getHolder().getSerialNumber());
            Principal[] issuer = x509AttributeCertificate.getHolder().getIssuer();
            int i2 = 0;
            while (i2 < issuer.length) {
                try {
                    if (issuer[i2] instanceof X500Principal) {
                        x509CertStoreSelector.setIssuer(((X500Principal) issuer[i2]).getEncoded());
                    }
                    hashSet.addAll(CertPathValidatorUtilities.findCertificates(x509CertStoreSelector, extendedPKIXParameters.getStores()));
                    i2++;
                } catch (Throwable e) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e);
                } catch (Throwable e2) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e2);
                }
            }
            if (hashSet.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
            }
        }
        if (x509AttributeCertificate.getHolder().getEntityNames() != null) {
            X509CertStoreSelector x509CertStoreSelector2 = new X509CertStoreSelector();
            Principal[] entityNames = x509AttributeCertificate.getHolder().getEntityNames();
            while (i < entityNames.length) {
                try {
                    if (entityNames[i] instanceof X500Principal) {
                        x509CertStoreSelector2.setIssuer(((X500Principal) entityNames[i]).getEncoded());
                    }
                    hashSet.addAll(CertPathValidatorUtilities.findCertificates(x509CertStoreSelector2, extendedPKIXParameters.getStores()));
                    i++;
                } catch (Throwable e22) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e22);
                } catch (Throwable e222) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e222);
                }
            }
            if (hashSet.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in entity name for attribute certificate cannot be found.");
            }
        }
        ExtendedPKIXBuilderParameters extendedPKIXBuilderParameters = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters.getInstance(extendedPKIXParameters);
        CertPathBuilderResult certPathBuilderResult2 = null;
        for (X509Certificate certificate : hashSet) {
            Selector x509CertStoreSelector3 = new X509CertStoreSelector();
            x509CertStoreSelector3.setCertificate(certificate);
            extendedPKIXBuilderParameters.setTargetConstraints(x509CertStoreSelector3);
            try {
                ExtCertPathValidatorException extCertPathValidatorException;
                try {
                    CertPathBuilderResult certPathBuilderResult3 = certPathBuilderResult2;
                    certPathBuilderResult2 = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME).build(ExtendedPKIXBuilderParameters.getInstance(extendedPKIXBuilderParameters));
                    extCertPathValidatorException = certPathBuilderResult3;
                } catch (Throwable e3) {
                    extCertPathValidatorException = new ExtCertPathValidatorException("Certification path for public key certificate of attribute certificate could not be build.", e3);
                    certPathBuilderResult2 = certPathBuilderResult;
                } catch (InvalidAlgorithmParameterException e4) {
                    throw new RuntimeException(e4.getMessage());
                }
                certPathBuilderResult = certPathBuilderResult2;
                Object obj = extCertPathValidatorException;
            } catch (Throwable e2222) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e2222);
            } catch (Throwable e22222) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e22222);
            }
        }
        if (certPathBuilderResult2 == null) {
            return certPathBuilderResult.getCertPath();
        }
        throw certPathBuilderResult2;
    }

    protected static CertPathValidatorResult processAttrCert2(CertPath certPath, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        try {
            try {
                return CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME).validate(certPath, extendedPKIXParameters);
            } catch (Throwable e) {
                throw new ExtCertPathValidatorException("Certification path for issuer certificate of attribute certificate could not be validated.", e);
            } catch (InvalidAlgorithmParameterException e2) {
                throw new RuntimeException(e2.getMessage());
            }
        } catch (Throwable e3) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e3);
        } catch (Throwable e32) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e32);
        }
    }

    protected static void processAttrCert3(X509Certificate x509Certificate, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        if (x509Certificate.getKeyUsage() != null && !x509Certificate.getKeyUsage()[0] && !x509Certificate.getKeyUsage()[1]) {
            throw new CertPathValidatorException("Attribute certificate issuer public key cannot be used to validate digital signatures.");
        } else if (x509Certificate.getBasicConstraints() != -1) {
            throw new CertPathValidatorException("Attribute certificate issuer is also a public key certificate issuer.");
        }
    }

    protected static void processAttrCert4(X509Certificate x509Certificate, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        Object obj = null;
        for (TrustAnchor trustAnchor : extendedPKIXParameters.getTrustedACIssuers()) {
            Object obj2 = (x509Certificate.getSubjectX500Principal().getName("RFC2253").equals(trustAnchor.getCAName()) || x509Certificate.equals(trustAnchor.getTrustedCert())) ? 1 : obj;
            obj = obj2;
        }
        if (obj == null) {
            throw new CertPathValidatorException("Attribute certificate issuer is not directly trusted.");
        }
    }

    protected static void processAttrCert5(X509AttributeCertificate x509AttributeCertificate, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        try {
            x509AttributeCertificate.checkValidity(CertPathValidatorUtilities.getValidDate(extendedPKIXParameters));
        } catch (Throwable e) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e);
        } catch (Throwable e2) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e2);
        }
    }

    protected static void processAttrCert7(X509AttributeCertificate x509AttributeCertificate, CertPath certPath, CertPath certPath2, ExtendedPKIXParameters extendedPKIXParameters) throws CertPathValidatorException {
        Object criticalExtensionOIDs = x509AttributeCertificate.getCriticalExtensionOIDs();
        if (criticalExtensionOIDs.contains(TARGET_INFORMATION)) {
            try {
                TargetInformation.getInstance(CertPathValidatorUtilities.getExtensionValue(x509AttributeCertificate, TARGET_INFORMATION));
            } catch (Throwable e) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e);
            } catch (Throwable e2) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e2);
            }
        }
        criticalExtensionOIDs.remove(TARGET_INFORMATION);
        for (PKIXAttrCertChecker check : extendedPKIXParameters.getAttrCertCheckers()) {
            check.check(x509AttributeCertificate, certPath, certPath2, criticalExtensionOIDs);
        }
        if (!criticalExtensionOIDs.isEmpty()) {
            throw new CertPathValidatorException("Attribute certificate contains unsupported critical extensions: " + criticalExtensionOIDs);
        }
    }
}
