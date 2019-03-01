package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.X509CertStoreSelector;

public class PKIXCertPathBuilderSpi extends CertPathBuilderSpi {
    private Exception certPathException;

    protected CertPathBuilderResult build(X509Certificate x509Certificate, ExtendedPKIXBuilderParameters extendedPKIXBuilderParameters, List list) {
        CertPathBuilderResult certPathBuilderResult = null;
        if (list.contains(x509Certificate)) {
            return null;
        }
        if (extendedPKIXBuilderParameters.getExcludedCerts().contains(x509Certificate)) {
            return null;
        }
        if (extendedPKIXBuilderParameters.getMaxPathLength() != -1 && list.size() - 1 > extendedPKIXBuilderParameters.getMaxPathLength()) {
            return null;
        }
        list.add(x509Certificate);
        try {
            CertificateFactory instance = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            CertPathValidator instance2 = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            CertPathBuilderResult certPathBuilderResult2;
            try {
                if (CertPathValidatorUtilities.findTrustAnchor(x509Certificate, extendedPKIXBuilderParameters.getTrustAnchors(), extendedPKIXBuilderParameters.getSigProvider()) != null) {
                    CertPath generateCertPath = instance.generateCertPath(list);
                    PKIXCertPathValidatorResult pKIXCertPathValidatorResult = (PKIXCertPathValidatorResult) instance2.validate(generateCertPath, extendedPKIXBuilderParameters);
                    return new PKIXCertPathBuilderResult(generateCertPath, pKIXCertPathValidatorResult.getTrustAnchor(), pKIXCertPathValidatorResult.getPolicyTree(), pKIXCertPathValidatorResult.getPublicKey());
                }
                CertPathValidatorUtilities.addAdditionalStoresFromAltNames(x509Certificate, extendedPKIXBuilderParameters);
                Collection hashSet = new HashSet();
                hashSet.addAll(CertPathValidatorUtilities.findIssuerCerts(x509Certificate, extendedPKIXBuilderParameters));
                if (hashSet.isEmpty()) {
                    throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
                }
                Iterator it = hashSet.iterator();
                while (it.hasNext() && certPathBuilderResult == null) {
                    certPathBuilderResult = build((X509Certificate) it.next(), extendedPKIXBuilderParameters, list);
                }
                certPathBuilderResult2 = certPathBuilderResult;
                if (certPathBuilderResult2 != null) {
                    return certPathBuilderResult2;
                }
                list.remove(x509Certificate);
                return certPathBuilderResult2;
            } catch (Throwable e) {
                throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", e);
            } catch (Throwable e2) {
                throw new AnnotatedException("No additiontal X.509 stores can be added from certificate locations.", e2);
            } catch (Throwable e22) {
                throw new AnnotatedException("Certification path could not be validated.", e22);
            } catch (Throwable e222) {
                throw new AnnotatedException("Certification path could not be constructed from certificate list.", e222);
            } catch (Exception e3) {
                this.certPathException = e3;
                certPathBuilderResult2 = null;
            }
        } catch (Exception e4) {
            throw new RuntimeException("Exception creating support classes.");
        }
    }

    public CertPathBuilderResult engineBuild(CertPathParameters certPathParameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        if ((certPathParameters instanceof PKIXBuilderParameters) || (certPathParameters instanceof ExtendedPKIXBuilderParameters)) {
            ExtendedPKIXBuilderParameters extendedPKIXBuilderParameters = certPathParameters instanceof ExtendedPKIXBuilderParameters ? (ExtendedPKIXBuilderParameters) certPathParameters : (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters.getInstance((PKIXBuilderParameters) certPathParameters);
            List arrayList = new ArrayList();
            Selector targetConstraints = extendedPKIXBuilderParameters.getTargetConstraints();
            if (targetConstraints instanceof X509CertStoreSelector) {
                try {
                    Collection findCertificates = CertPathValidatorUtilities.findCertificates((X509CertStoreSelector) targetConstraints, extendedPKIXBuilderParameters.getStores());
                    findCertificates.addAll(CertPathValidatorUtilities.findCertificates((X509CertStoreSelector) targetConstraints, extendedPKIXBuilderParameters.getCertStores()));
                    if (findCertificates.isEmpty()) {
                        throw new CertPathBuilderException("No certificate found matching targetContraints.");
                    }
                    CertPathBuilderResult certPathBuilderResult = null;
                    Iterator it = findCertificates.iterator();
                    while (it.hasNext() && certPathBuilderResult == null) {
                        certPathBuilderResult = build((X509Certificate) it.next(), extendedPKIXBuilderParameters, arrayList);
                    }
                    if (certPathBuilderResult != null || this.certPathException == null) {
                        if (certPathBuilderResult != null || this.certPathException != null) {
                            return certPathBuilderResult;
                        }
                        throw new CertPathBuilderException("Unable to find certificate chain.");
                    } else if (this.certPathException instanceof AnnotatedException) {
                        throw new CertPathBuilderException(this.certPathException.getMessage(), this.certPathException.getCause());
                    } else {
                        throw new CertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
                    }
                } catch (Throwable e) {
                    throw new ExtCertPathBuilderException("Error finding target certificate.", e);
                }
            }
            throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509CertStoreSelector.class.getName() + " for " + getClass().getName() + " class.");
        }
        throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + ExtendedPKIXBuilderParameters.class.getName() + ".");
    }
}
