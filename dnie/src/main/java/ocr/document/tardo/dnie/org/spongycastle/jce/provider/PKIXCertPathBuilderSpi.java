package org.spongycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.spongycastle.jce.exception.ExtCertPathBuilderException;
import org.spongycastle.util.Selector;
import org.spongycastle.x509.ExtendedPKIXBuilderParameters;
import org.spongycastle.x509.X509CertStoreSelector;

public class PKIXCertPathBuilderSpi extends CertPathBuilderSpi {
    private Exception certPathException;

    public CertPathBuilderResult engineBuild(CertPathParameters params) throws CertPathBuilderException, InvalidAlgorithmParameterException {
        if ((params instanceof PKIXBuilderParameters) || (params instanceof ExtendedPKIXBuilderParameters)) {
            ExtendedPKIXBuilderParameters pkixParams;
            if (params instanceof ExtendedPKIXBuilderParameters) {
                pkixParams = (ExtendedPKIXBuilderParameters) params;
            } else {
                pkixParams = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters.getInstance((PKIXBuilderParameters) params);
            }
            List certPathList = new ArrayList();
            Selector certSelect = pkixParams.getTargetConstraints();
            if (certSelect instanceof X509CertStoreSelector) {
                try {
                    Collection targets = CertPathValidatorUtilities.findCertificates((X509CertStoreSelector) certSelect, pkixParams.getStores());
                    targets.addAll(CertPathValidatorUtilities.findCertificates((X509CertStoreSelector) certSelect, pkixParams.getCertStores()));
                    if (targets.isEmpty()) {
                        throw new CertPathBuilderException("No certificate found matching targetContraints.");
                    }
                    CertPathBuilderResult result = null;
                    Iterator targetIter = targets.iterator();
                    while (targetIter.hasNext() && result == null) {
                        result = build((X509Certificate) targetIter.next(), pkixParams, certPathList);
                    }
                    if (result != null || this.certPathException == null) {
                        if (result != null || this.certPathException != null) {
                            return result;
                        }
                        throw new CertPathBuilderException("Unable to find certificate chain.");
                    } else if (this.certPathException instanceof AnnotatedException) {
                        throw new CertPathBuilderException(this.certPathException.getMessage(), this.certPathException.getCause());
                    } else {
                        throw new CertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
                    }
                } catch (AnnotatedException e) {
                    throw new ExtCertPathBuilderException("Error finding target certificate.", e);
                }
            }
            throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509CertStoreSelector.class.getName() + " for " + getClass().getName() + " class.");
        }
        throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + ExtendedPKIXBuilderParameters.class.getName() + ".");
    }

    protected CertPathBuilderResult build(X509Certificate tbvCert, ExtendedPKIXBuilderParameters pkixParams, List tbvPath) {
        if (tbvPath.contains(tbvCert)) {
            return null;
        }
        if (pkixParams.getExcludedCerts().contains(tbvCert)) {
            return null;
        }
        if (pkixParams.getMaxPathLength() != -1 && tbvPath.size() - 1 > pkixParams.getMaxPathLength()) {
            return null;
        }
        tbvPath.add(tbvCert);
        CertPathBuilderResult builderResult = null;
        try {
            CertificateFactory cFact = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            try {
                if (CertPathValidatorUtilities.findTrustAnchor(tbvCert, pkixParams.getTrustAnchors(), pkixParams.getSigProvider()) != null) {
                    CertPath certPath = cFact.generateCertPath(tbvPath);
                    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, pkixParams);
                    return new PKIXCertPathBuilderResult(certPath, result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey());
                }
                CertPathValidatorUtilities.addAdditionalStoresFromAltNames(tbvCert, pkixParams);
                Collection issuers = new HashSet();
                issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, pkixParams));
                if (issuers.isEmpty()) {
                    throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
                }
                Iterator it = issuers.iterator();
                while (it.hasNext() && builderResult == null) {
                    builderResult = build((X509Certificate) it.next(), pkixParams, tbvPath);
                }
                if (builderResult != null) {
                    return builderResult;
                }
                tbvPath.remove(tbvCert);
                return builderResult;
            } catch (AnnotatedException e) {
                throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", e);
            } catch (CertificateParsingException e2) {
                throw new AnnotatedException("No additiontal X.509 stores can be added from certificate locations.", e2);
            } catch (Exception e3) {
                throw new AnnotatedException("Certification path could not be validated.", e3);
            } catch (Exception e32) {
                throw new AnnotatedException("Certification path could not be constructed from certificate list.", e32);
            } catch (AnnotatedException e4) {
                this.certPathException = e4;
            }
        } catch (Exception e5) {
            throw new RuntimeException("Exception creating support classes.");
        }
    }
}
