package org.spongycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.X509Certificate;
import org.spongycastle.jce.exception.ExtCertPathValidatorException;
import org.spongycastle.util.Selector;
import org.spongycastle.x509.ExtendedPKIXParameters;
import org.spongycastle.x509.X509AttributeCertStoreSelector;
import org.spongycastle.x509.X509AttributeCertificate;

public class PKIXAttrCertPathValidatorSpi extends CertPathValidatorSpi {
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        if (params instanceof ExtendedPKIXParameters) {
            ExtendedPKIXParameters pkixParams = (ExtendedPKIXParameters) params;
            Selector certSelect = pkixParams.getTargetConstraints();
            if (certSelect instanceof X509AttributeCertStoreSelector) {
                X509AttributeCertificate attrCert = ((X509AttributeCertStoreSelector) certSelect).getAttributeCert();
                CertPath holderCertPath = RFC3281CertPathUtilities.processAttrCert1(attrCert, pkixParams);
                CertPathValidatorResult result = RFC3281CertPathUtilities.processAttrCert2(certPath, pkixParams);
                X509Certificate issuerCert = (X509Certificate) certPath.getCertificates().get(0);
                RFC3281CertPathUtilities.processAttrCert3(issuerCert, pkixParams);
                RFC3281CertPathUtilities.processAttrCert4(issuerCert, pkixParams);
                RFC3281CertPathUtilities.processAttrCert5(attrCert, pkixParams);
                RFC3281CertPathUtilities.processAttrCert7(attrCert, certPath, holderCertPath, pkixParams);
                RFC3281CertPathUtilities.additionalChecks(attrCert, pkixParams);
                try {
                    RFC3281CertPathUtilities.checkCRLs(attrCert, pkixParams, issuerCert, CertPathValidatorUtilities.getValidCertDateFromValidityModel(pkixParams, null, -1), certPath.getCertificates());
                    return result;
                } catch (AnnotatedException e) {
                    throw new ExtCertPathValidatorException("Could not get validity date from attribute certificate.", e);
                }
            }
            throw new InvalidAlgorithmParameterException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + getClass().getName() + " class.");
        }
        throw new InvalidAlgorithmParameterException("Parameters must be a " + ExtendedPKIXParameters.class.getName() + " instance.");
    }
}
