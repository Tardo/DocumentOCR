package org.spongycastle.jce.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.spongycastle.jce.X509LDAPCertStoreParameters;
import org.spongycastle.util.Selector;
import org.spongycastle.util.StoreException;
import org.spongycastle.x509.X509CertPairStoreSelector;
import org.spongycastle.x509.X509CertStoreSelector;
import org.spongycastle.x509.X509CertificatePair;
import org.spongycastle.x509.X509StoreParameters;
import org.spongycastle.x509.X509StoreSpi;
import org.spongycastle.x509.util.LDAPStoreHelper;

public class X509StoreLDAPCerts extends X509StoreSpi {
    private LDAPStoreHelper helper;

    public void engineInit(X509StoreParameters params) {
        if (params instanceof X509LDAPCertStoreParameters) {
            this.helper = new LDAPStoreHelper((X509LDAPCertStoreParameters) params);
            return;
        }
        throw new IllegalArgumentException("Initialization parameters must be an instance of " + X509LDAPCertStoreParameters.class.getName() + ".");
    }

    public Collection engineGetMatches(Selector selector) throws StoreException {
        if (!(selector instanceof X509CertStoreSelector)) {
            return Collections.EMPTY_SET;
        }
        X509CertStoreSelector xselector = (X509CertStoreSelector) selector;
        Collection set = new HashSet();
        if (xselector.getBasicConstraints() > 0) {
            set.addAll(this.helper.getCACertificates(xselector));
            set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
            return set;
        } else if (xselector.getBasicConstraints() == -2) {
            set.addAll(this.helper.getUserCertificates(xselector));
            return set;
        } else {
            set.addAll(this.helper.getUserCertificates(xselector));
            set.addAll(this.helper.getCACertificates(xselector));
            set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
            return set;
        }
    }

    private Collection getCertificatesFromCrossCertificatePairs(X509CertStoreSelector xselector) throws StoreException {
        Set set = new HashSet();
        X509CertPairStoreSelector ps = new X509CertPairStoreSelector();
        ps.setForwardSelector(xselector);
        ps.setReverseSelector(new X509CertStoreSelector());
        Set<X509CertificatePair> crossCerts = new HashSet(this.helper.getCrossCertificatePairs(ps));
        Set forward = new HashSet();
        Set reverse = new HashSet();
        for (X509CertificatePair pair : crossCerts) {
            if (pair.getForward() != null) {
                forward.add(pair.getForward());
            }
            if (pair.getReverse() != null) {
                reverse.add(pair.getReverse());
            }
        }
        set.addAll(forward);
        set.addAll(reverse);
        return set;
    }
}
