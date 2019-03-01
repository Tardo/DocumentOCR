package org.spongycastle.jce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.x509.CRLDistPoint;
import org.spongycastle.asn1.x509.DistributionPoint;
import org.spongycastle.asn1.x509.DistributionPointName;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.TargetInformation;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.exception.ExtCertPathValidatorException;
import org.spongycastle.x509.ExtendedPKIXBuilderParameters;
import org.spongycastle.x509.ExtendedPKIXParameters;
import org.spongycastle.x509.PKIXAttrCertChecker;
import org.spongycastle.x509.X509AttributeCertificate;
import org.spongycastle.x509.X509CertStoreSelector;

class RFC3281CertPathUtilities {
    private static final String AUTHORITY_INFO_ACCESS = X509Extensions.AuthorityInfoAccess.getId();
    private static final String CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
    private static final String NO_REV_AVAIL = X509Extensions.NoRevAvail.getId();
    private static final String TARGET_INFORMATION = X509Extensions.TargetInformation.getId();

    RFC3281CertPathUtilities() {
    }

    protected static void processAttrCert7(X509AttributeCertificate attrCert, CertPath certPath, CertPath holderCertPath, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        Set set = attrCert.getCriticalExtensionOIDs();
        if (set.contains(TARGET_INFORMATION)) {
            try {
                TargetInformation.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, TARGET_INFORMATION));
            } catch (AnnotatedException e) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e);
            } catch (IllegalArgumentException e2) {
                throw new ExtCertPathValidatorException("Target information extension could not be read.", e2);
            }
        }
        set.remove(TARGET_INFORMATION);
        for (PKIXAttrCertChecker check : pkixParams.getAttrCertCheckers()) {
            check.check(attrCert, certPath, holderCertPath, set);
        }
        if (!set.isEmpty()) {
            throw new CertPathValidatorException("Attribute certificate contains unsupported critical extensions: " + set);
        }
    }

    protected static void checkCRLs(X509AttributeCertificate attrCert, ExtendedPKIXParameters paramsPKIX, X509Certificate issuerCert, Date validDate, List certPathCerts) throws CertPathValidatorException {
        if (paramsPKIX.isRevocationEnabled()) {
            if (attrCert.getExtensionValue(NO_REV_AVAIL) == null) {
                try {
                    CRLDistPoint crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, CRL_DISTRIBUTION_POINTS));
                    try {
                        CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX);
                        CertStatus certStatus = new CertStatus();
                        ReasonsMask reasonsMask = new ReasonsMask();
                        AnnotatedException annotatedException = null;
                        boolean z = false;
                        if (crldp != null) {
                            try {
                                DistributionPoint[] dps = crldp.getDistributionPoints();
                                int i = 0;
                                while (i < dps.length && certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                                    try {
                                        checkCRL(dps[i], attrCert, (ExtendedPKIXParameters) paramsPKIX.clone(), validDate, issuerCert, certStatus, reasonsMask, certPathCerts);
                                        z = true;
                                        i++;
                                    } catch (AnnotatedException e) {
                                        annotatedException = new AnnotatedException("No valid CRL for distribution point found.", e);
                                    }
                                }
                            } catch (Exception e2) {
                                throw new ExtCertPathValidatorException("Distribution points could not be read.", e2);
                            }
                        }
                        if (certStatus.getCertStatus() == 11 && !reasonsMask.isAllReasons()) {
                            try {
                                checkCRL(new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(4, new ASN1InputStream(((X500Principal) attrCert.getIssuer().getPrincipals()[0]).getEncoded()).readObject()))), null, null), attrCert, (ExtendedPKIXParameters) paramsPKIX.clone(), validDate, issuerCert, certStatus, reasonsMask, certPathCerts);
                                z = true;
                            } catch (Exception e22) {
                                throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", e22);
                            } catch (AnnotatedException e3) {
                                annotatedException = new AnnotatedException("No valid CRL for distribution point found.", e3);
                            }
                        }
                        if (!z) {
                            throw new ExtCertPathValidatorException("No valid CRL found.", annotatedException);
                        } else if (certStatus.getCertStatus() != 11) {
                            throw new CertPathValidatorException(("Attribute certificate revocation after " + certStatus.getRevocationDate()) + ", reason: " + RFC3280CertPathUtilities.crlReasons[certStatus.getCertStatus()]);
                        } else {
                            if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == 11) {
                                certStatus.setCertStatus(12);
                            }
                            if (certStatus.getCertStatus() == 12) {
                                throw new CertPathValidatorException("Attribute certificate status could not be determined.");
                            }
                            return;
                        }
                    } catch (AnnotatedException e32) {
                        throw new CertPathValidatorException("No additional CRL locations could be decoded from CRL distribution point extension.", e32);
                    }
                } catch (AnnotatedException e322) {
                    throw new CertPathValidatorException("CRL distribution point extension could not be read.", e322);
                }
            }
            if (attrCert.getExtensionValue(CRL_DISTRIBUTION_POINTS) == null) {
                if (attrCert.getExtensionValue(AUTHORITY_INFO_ACCESS) == null) {
                    return;
                }
            }
            throw new CertPathValidatorException("No rev avail extension is set, but also an AC revocation pointer.");
        }
    }

    protected static void additionalChecks(X509AttributeCertificate attrCert, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        for (String oid : pkixParams.getProhibitedACAttributes()) {
            if (attrCert.getAttributes(oid) != null) {
                throw new CertPathValidatorException("Attribute certificate contains prohibited attribute: " + oid + ".");
            }
        }
        for (String oid2 : pkixParams.getNecessaryACAttributes()) {
            if (attrCert.getAttributes(oid2) == null) {
                throw new CertPathValidatorException("Attribute certificate does not contain necessary attribute: " + oid2 + ".");
            }
        }
    }

    protected static void processAttrCert5(X509AttributeCertificate attrCert, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        try {
            attrCert.checkValidity(CertPathValidatorUtilities.getValidDate(pkixParams));
        } catch (CertificateExpiredException e) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e);
        } catch (CertificateNotYetValidException e2) {
            throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e2);
        }
    }

    protected static void processAttrCert4(X509Certificate acIssuerCert, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        boolean trusted = false;
        for (TrustAnchor anchor : pkixParams.getTrustedACIssuers()) {
            if (acIssuerCert.getSubjectX500Principal().getName("RFC2253").equals(anchor.getCAName()) || acIssuerCert.equals(anchor.getTrustedCert())) {
                trusted = true;
            }
        }
        if (!trusted) {
            throw new CertPathValidatorException("Attribute certificate issuer is not directly trusted.");
        }
    }

    protected static void processAttrCert3(X509Certificate acIssuerCert, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        if (acIssuerCert.getKeyUsage() != null && !acIssuerCert.getKeyUsage()[0] && !acIssuerCert.getKeyUsage()[1]) {
            throw new CertPathValidatorException("Attribute certificate issuer public key cannot be used to validate digital signatures.");
        } else if (acIssuerCert.getBasicConstraints() != -1) {
            throw new CertPathValidatorException("Attribute certificate issuer is also a public key certificate issuer.");
        }
    }

    protected static CertPathValidatorResult processAttrCert2(CertPath certPath, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        try {
            try {
                return CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME).validate(certPath, pkixParams);
            } catch (CertPathValidatorException e) {
                throw new ExtCertPathValidatorException("Certification path for issuer certificate of attribute certificate could not be validated.", e);
            } catch (InvalidAlgorithmParameterException e2) {
                throw new RuntimeException(e2.getMessage());
            }
        } catch (NoSuchProviderException e3) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e3);
        } catch (NoSuchAlgorithmException e4) {
            throw new ExtCertPathValidatorException("Support class could not be created.", e4);
        }
    }

    protected static CertPath processAttrCert1(X509AttributeCertificate attrCert, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException {
        X509CertStoreSelector selector;
        Principal[] principals;
        int i;
        CertPathBuilderResult result = null;
        Set<X509Certificate> holderPKCs = new HashSet();
        if (attrCert.getHolder().getIssuer() != null) {
            selector = new X509CertStoreSelector();
            selector.setSerialNumber(attrCert.getHolder().getSerialNumber());
            principals = attrCert.getHolder().getIssuer();
            i = 0;
            while (i < principals.length) {
                try {
                    if (principals[i] instanceof X500Principal) {
                        selector.setIssuer(((X500Principal) principals[i]).getEncoded());
                    }
                    holderPKCs.addAll(CertPathValidatorUtilities.findCertificates(selector, pkixParams.getStores()));
                    i++;
                } catch (AnnotatedException e) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e);
                } catch (IOException e2) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e2);
                }
            }
            if (holderPKCs.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
            }
        }
        if (attrCert.getHolder().getEntityNames() != null) {
            selector = new X509CertStoreSelector();
            principals = attrCert.getHolder().getEntityNames();
            i = 0;
            while (i < principals.length) {
                try {
                    if (principals[i] instanceof X500Principal) {
                        selector.setIssuer(((X500Principal) principals[i]).getEncoded());
                    }
                    holderPKCs.addAll(CertPathValidatorUtilities.findCertificates(selector, pkixParams.getStores()));
                    i++;
                } catch (AnnotatedException e3) {
                    throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e3);
                } catch (IOException e22) {
                    throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e22);
                }
            }
            if (holderPKCs.isEmpty()) {
                throw new CertPathValidatorException("Public key certificate specified in entity name for attribute certificate cannot be found.");
            }
        }
        ExtendedPKIXBuilderParameters params = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters.getInstance(pkixParams);
        CertPathValidatorException lastException = null;
        for (X509Certificate certificate : holderPKCs) {
            selector = new X509CertStoreSelector();
            selector.setCertificate(certificate);
            params.setTargetConstraints(selector);
            try {
                try {
                    result = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME).build(ExtendedPKIXBuilderParameters.getInstance(params));
                } catch (CertPathBuilderException e4) {
                    lastException = new ExtCertPathValidatorException("Certification path for public key certificate of attribute certificate could not be build.", e4);
                } catch (InvalidAlgorithmParameterException e5) {
                    throw new RuntimeException(e5.getMessage());
                }
            } catch (NoSuchProviderException e6) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e6);
            } catch (NoSuchAlgorithmException e7) {
                throw new ExtCertPathValidatorException("Support class could not be created.", e7);
            }
        }
        if (lastException == null) {
            return result.getCertPath();
        }
        throw lastException;
    }

    private static void checkCRL(DistributionPoint dp, X509AttributeCertificate attrCert, ExtendedPKIXParameters paramsPKIX, Date validDate, X509Certificate issuerCert, CertStatus certStatus, ReasonsMask reasonMask, List certPathCerts) throws AnnotatedException {
        if (attrCert.getExtensionValue(X509Extensions.NoRevAvail.getId()) == null) {
            Date currentDate = new Date(System.currentTimeMillis());
            if (validDate.getTime() > currentDate.getTime()) {
                throw new AnnotatedException("Validation time is in future.");
            }
            boolean validCrlFound = false;
            AnnotatedException lastException = null;
            Iterator crl_iter = CertPathValidatorUtilities.getCompleteCRLs(dp, attrCert, currentDate, paramsPKIX).iterator();
            while (crl_iter.hasNext() && certStatus.getCertStatus() == 11 && !reasonMask.isAllReasons()) {
                try {
                    X509CRL crl = (X509CRL) crl_iter.next();
                    ReasonsMask interimReasonsMask = RFC3280CertPathUtilities.processCRLD(crl, dp);
                    if (interimReasonsMask.hasNewReasons(reasonMask)) {
                        PublicKey key = RFC3280CertPathUtilities.processCRLG(crl, RFC3280CertPathUtilities.processCRLF(crl, attrCert, null, null, paramsPKIX, certPathCerts));
                        X509CRL deltaCRL = null;
                        if (paramsPKIX.isUseDeltasEnabled()) {
                            deltaCRL = RFC3280CertPathUtilities.processCRLH(CertPathValidatorUtilities.getDeltaCRLs(currentDate, paramsPKIX, crl), key);
                        }
                        if (paramsPKIX.getValidityModel() == 1 || attrCert.getNotAfter().getTime() >= crl.getThisUpdate().getTime()) {
                            RFC3280CertPathUtilities.processCRLB1(dp, attrCert, crl);
                            RFC3280CertPathUtilities.processCRLB2(dp, attrCert, crl);
                            RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);
                            RFC3280CertPathUtilities.processCRLI(validDate, deltaCRL, attrCert, certStatus, paramsPKIX);
                            RFC3280CertPathUtilities.processCRLJ(validDate, crl, attrCert, certStatus);
                            if (certStatus.getCertStatus() == 8) {
                                certStatus.setCertStatus(11);
                            }
                            reasonMask.addReasons(interimReasonsMask);
                            validCrlFound = true;
                        } else {
                            throw new AnnotatedException("No valid CRL for current time found.");
                        }
                    }
                    continue;
                } catch (AnnotatedException e) {
                    lastException = e;
                }
            }
            if (!validCrlFound) {
                throw lastException;
            }
        }
    }
}
