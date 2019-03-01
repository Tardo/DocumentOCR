package org.spongycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.spongycastle.jce.MultiCertStoreParameters;

public class MultiCertStoreSpi extends CertStoreSpi {
    private MultiCertStoreParameters params;

    public MultiCertStoreSpi(CertStoreParameters params) throws InvalidAlgorithmParameterException {
        super(params);
        if (params instanceof MultiCertStoreParameters) {
            this.params = (MultiCertStoreParameters) params;
            return;
        }
        throw new InvalidAlgorithmParameterException("org.spongycastle.jce.provider.MultiCertStoreSpi: parameter must be a MultiCertStoreParameters object\n" + params.toString());
    }

    public Collection engineGetCertificates(CertSelector certSelector) throws CertStoreException {
        boolean searchAllStores = this.params.getSearchAllStores();
        List allCerts = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;
        for (CertStore store : this.params.getCertStores()) {
            Collection certs = store.getCertificates(certSelector);
            if (searchAllStores) {
                allCerts.addAll(certs);
            } else if (!certs.isEmpty()) {
                return certs;
            }
        }
        return allCerts;
    }

    public Collection engineGetCRLs(CRLSelector crlSelector) throws CertStoreException {
        boolean searchAllStores = this.params.getSearchAllStores();
        List allCRLs = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;
        for (CertStore store : this.params.getCertStores()) {
            Collection crls = store.getCRLs(crlSelector);
            if (searchAllStores) {
                allCRLs.addAll(crls);
            } else if (!crls.isEmpty()) {
                return crls;
            }
        }
        return allCRLs;
    }
}
