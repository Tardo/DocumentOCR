package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREnumerated;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.CRLDistPoint;
import org.spongycastle.asn1.x509.CertificateList;
import org.spongycastle.asn1.x509.DistributionPoint;
import org.spongycastle.asn1.x509.DistributionPointName;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.PolicyInformation;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.X509LDAPCertStoreParameters.Builder;
import org.spongycastle.jce.exception.ExtCertPathValidatorException;
import org.spongycastle.util.StoreException;
import org.spongycastle.x509.ExtendedPKIXBuilderParameters;
import org.spongycastle.x509.ExtendedPKIXParameters;
import org.spongycastle.x509.X509AttributeCertStoreSelector;
import org.spongycastle.x509.X509AttributeCertificate;
import org.spongycastle.x509.X509CRLStoreSelector;
import org.spongycastle.x509.X509CertStoreSelector;
import org.spongycastle.x509.X509Store;
import org.spongycastle.x509.X509StoreParameters;

public class CertPathValidatorUtilities {
    protected static final String ANY_POLICY = "2.5.29.32.0";
    protected static final String AUTHORITY_KEY_IDENTIFIER = X509Extensions.AuthorityKeyIdentifier.getId();
    protected static final String BASIC_CONSTRAINTS = X509Extensions.BasicConstraints.getId();
    protected static final String CERTIFICATE_POLICIES = X509Extensions.CertificatePolicies.getId();
    protected static final String CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
    protected static final String CRL_NUMBER = X509Extensions.CRLNumber.getId();
    protected static final int CRL_SIGN = 6;
    protected static final PKIXCRLUtil CRL_UTIL = new PKIXCRLUtil();
    protected static final String DELTA_CRL_INDICATOR = X509Extensions.DeltaCRLIndicator.getId();
    protected static final String FRESHEST_CRL = X509Extensions.FreshestCRL.getId();
    protected static final String INHIBIT_ANY_POLICY = X509Extensions.InhibitAnyPolicy.getId();
    protected static final String ISSUING_DISTRIBUTION_POINT = X509Extensions.IssuingDistributionPoint.getId();
    protected static final int KEY_CERT_SIGN = 5;
    protected static final String KEY_USAGE = X509Extensions.KeyUsage.getId();
    protected static final String NAME_CONSTRAINTS = X509Extensions.NameConstraints.getId();
    protected static final String POLICY_CONSTRAINTS = X509Extensions.PolicyConstraints.getId();
    protected static final String POLICY_MAPPINGS = X509Extensions.PolicyMappings.getId();
    protected static final String SUBJECT_ALTERNATIVE_NAME = X509Extensions.SubjectAlternativeName.getId();
    protected static final String[] crlReasons = new String[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};

    protected static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors) throws AnnotatedException {
        return findTrustAnchor(cert, trustAnchors, null);
    }

    protected static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors, String sigProvider) throws AnnotatedException {
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;
        X509CertSelector certSelectX509 = new X509CertSelector();
        X500Principal certIssuer = getEncodedIssuerPrincipal(cert);
        try {
            certSelectX509.setSubject(certIssuer.getEncoded());
            Iterator iter = trustAnchors.iterator();
            while (iter.hasNext() && trust == null) {
                trust = (TrustAnchor) iter.next();
                if (trust.getTrustedCert() != null) {
                    if (certSelectX509.match(trust.getTrustedCert())) {
                        trustPublicKey = trust.getTrustedCert().getPublicKey();
                    } else {
                        trust = null;
                    }
                } else if (trust.getCAName() == null || trust.getCAPublicKey() == null) {
                    trust = null;
                } else {
                    try {
                        if (certIssuer.equals(new X500Principal(trust.getCAName()))) {
                            trustPublicKey = trust.getCAPublicKey();
                        } else {
                            trust = null;
                        }
                    } catch (IllegalArgumentException e) {
                        trust = null;
                    }
                }
                if (trustPublicKey != null) {
                    try {
                        verifyX509Certificate(cert, trustPublicKey, sigProvider);
                    } catch (Exception ex) {
                        invalidKeyEx = ex;
                        trust = null;
                    }
                }
            }
            if (trust != null || invalidKeyEx == null) {
                return trust;
            }
            throw new AnnotatedException("TrustAnchor found but certificate validation failed.", invalidKeyEx);
        } catch (IOException ex2) {
            throw new AnnotatedException("Cannot set subject search criteria for trust anchor.", ex2);
        }
    }

    protected static void addAdditionalStoresFromAltNames(X509Certificate cert, ExtendedPKIXParameters pkixParams) throws CertificateParsingException {
        if (cert.getIssuerAlternativeNames() != null) {
            for (List list : cert.getIssuerAlternativeNames()) {
                if (list.get(0).equals(new Integer(6))) {
                    addAdditionalStoreFromLocation((String) list.get(1), pkixParams);
                }
            }
        }
    }

    protected static X500Principal getEncodedIssuerPrincipal(Object cert) {
        if (cert instanceof X509Certificate) {
            return ((X509Certificate) cert).getIssuerX500Principal();
        }
        return (X500Principal) ((X509AttributeCertificate) cert).getIssuer().getPrincipals()[0];
    }

    protected static Date getValidDate(PKIXParameters paramsPKIX) {
        Date validDate = paramsPKIX.getDate();
        if (validDate == null) {
            return new Date();
        }
        return validDate;
    }

    protected static X500Principal getSubjectPrincipal(X509Certificate cert) {
        return cert.getSubjectX500Principal();
    }

    protected static boolean isSelfIssued(X509Certificate cert) {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }

    protected static DERObject getExtensionValue(X509Extension ext, String oid) throws AnnotatedException {
        byte[] bytes = ext.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        return getObject(oid, bytes);
    }

    private static DERObject getObject(String oid, byte[] ext) throws AnnotatedException {
        try {
            return new ASN1InputStream(((ASN1OctetString) new ASN1InputStream(ext).readObject()).getOctets()).readObject();
        } catch (Exception e) {
            throw new AnnotatedException("exception processing extension " + oid, e);
        }
    }

    protected static X500Principal getIssuerPrincipal(X509CRL crl) {
        return crl.getIssuerX500Principal();
    }

    protected static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey key) throws CertPathValidatorException {
        try {
            return SubjectPublicKeyInfo.getInstance(new ASN1InputStream(key.getEncoded()).readObject()).getAlgorithmId();
        } catch (Exception e) {
            throw new ExtCertPathValidatorException("Subject public key cannot be decoded.", e);
        }
    }

    protected static final Set getQualifierSet(ASN1Sequence qualifiers) throws CertPathValidatorException {
        Set pq = new HashSet();
        if (qualifiers != null) {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream aOut = new ASN1OutputStream(bOut);
            Enumeration e = qualifiers.getObjects();
            while (e.hasMoreElements()) {
                try {
                    aOut.writeObject(e.nextElement());
                    pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
                    bOut.reset();
                } catch (IOException ex) {
                    throw new ExtCertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
                }
            }
        }
        return pq;
    }

    protected static PKIXPolicyNode removePolicyNode(PKIXPolicyNode validPolicyTree, List[] policyNodes, PKIXPolicyNode _node) {
        PKIXPolicyNode _parent = (PKIXPolicyNode) _node.getParent();
        if (validPolicyTree == null) {
            return null;
        }
        if (_parent == null) {
            for (int j = 0; j < policyNodes.length; j++) {
                policyNodes[j] = new ArrayList();
            }
            return null;
        }
        _parent.removeChild(_node);
        removePolicyNodeRecurse(policyNodes, _node);
        return validPolicyTree;
    }

    private static void removePolicyNodeRecurse(List[] policyNodes, PKIXPolicyNode _node) {
        policyNodes[_node.getDepth()].remove(_node);
        if (_node.hasChildren()) {
            Iterator _iter = _node.getChildren();
            while (_iter.hasNext()) {
                removePolicyNodeRecurse(policyNodes, (PKIXPolicyNode) _iter.next());
            }
        }
    }

    protected static boolean processCertD1i(int index, List[] policyNodes, DERObjectIdentifier pOid, Set pq) {
        List policyNodeVec = policyNodes[index - 1];
        for (int j = 0; j < policyNodeVec.size(); j++) {
            PKIXPolicyNode node = (PKIXPolicyNode) policyNodeVec.get(j);
            if (node.getExpectedPolicies().contains(pOid.getId())) {
                Set childExpectedPolicies = new HashSet();
                childExpectedPolicies.add(pOid.getId());
                PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(), index, childExpectedPolicies, node, pq, pOid.getId(), false);
                node.addChild(child);
                policyNodes[index].add(child);
                return true;
            }
        }
        return false;
    }

    protected static void processCertD1ii(int index, List[] policyNodes, DERObjectIdentifier _poid, Set _pq) {
        List policyNodeVec = policyNodes[index - 1];
        for (int j = 0; j < policyNodeVec.size(); j++) {
            PKIXPolicyNode _node = (PKIXPolicyNode) policyNodeVec.get(j);
            if ("2.5.29.32.0".equals(_node.getValidPolicy())) {
                Set _childExpectedPolicies = new HashSet();
                _childExpectedPolicies.add(_poid.getId());
                PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(), index, _childExpectedPolicies, _node, _pq, _poid.getId(), false);
                _node.addChild(_child);
                policyNodes[index].add(_child);
                return;
            }
        }
    }

    protected static void prepareNextCertB1(int i, List[] policyNodes, String id_p, Map m_idp, X509Certificate cert) throws AnnotatedException, CertPathValidatorException {
        boolean idp_found = false;
        for (PKIXPolicyNode node : policyNodes[i]) {
            if (node.getValidPolicy().equals(id_p)) {
                idp_found = true;
                node.expectedPolicies = (Set) m_idp.get(id_p);
                break;
            }
        }
        if (!idp_found) {
            for (PKIXPolicyNode node2 : policyNodes[i]) {
                if ("2.5.29.32.0".equals(node2.getValidPolicy())) {
                    Set pq = null;
                    Enumeration e;
                    try {
                        e = ASN1Sequence.getInstance(getExtensionValue(cert, CERTIFICATE_POLICIES)).getObjects();
                        while (e.hasMoreElements()) {
                            try {
                                PolicyInformation pinfo = PolicyInformation.getInstance(e.nextElement());
                                if ("2.5.29.32.0".equals(pinfo.getPolicyIdentifier().getId())) {
                                    try {
                                        pq = getQualifierSet(pinfo.getPolicyQualifiers());
                                        break;
                                    } catch (CertPathValidatorException ex) {
                                        throw new ExtCertPathValidatorException("Policy qualifier info set could not be built.", ex);
                                    }
                                }
                            } catch (Exception ex2) {
                                throw new AnnotatedException("Policy information cannot be decoded.", ex2);
                            }
                        }
                        boolean ci = false;
                        if (cert.getCriticalExtensionOIDs() != null) {
                            ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                        }
                        PKIXPolicyNode p_node = (PKIXPolicyNode) node2.getParent();
                        if ("2.5.29.32.0".equals(p_node.getValidPolicy())) {
                            PKIXPolicyNode c_node = new PKIXPolicyNode(new ArrayList(), i, (Set) m_idp.get(id_p), p_node, pq, id_p, ci);
                            p_node.addChild(c_node);
                            policyNodes[i].add(c_node);
                            return;
                        }
                        return;
                    } catch (Enumeration e2) {
                        throw new AnnotatedException("Certificate policies cannot be decoded.", e2);
                    }
                }
            }
        }
    }

    protected static PKIXPolicyNode prepareNextCertB2(int i, List[] policyNodes, String id_p, PKIXPolicyNode validPolicyTree) {
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext()) {
            PKIXPolicyNode node = (PKIXPolicyNode) nodes_i.next();
            if (node.getValidPolicy().equals(id_p)) {
                ((PKIXPolicyNode) node.getParent()).removeChild(node);
                nodes_i.remove();
                for (int k = i - 1; k >= 0; k--) {
                    List nodes = policyNodes[k];
                    for (int l = 0; l < nodes.size(); l++) {
                        PKIXPolicyNode node2 = (PKIXPolicyNode) nodes.get(l);
                        if (!node2.hasChildren()) {
                            validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
                            if (validPolicyTree == null) {
                                break;
                            }
                        }
                    }
                }
            }
        }
        return validPolicyTree;
    }

    protected static boolean isAnyPolicy(Set policySet) {
        return policySet == null || policySet.contains("2.5.29.32.0") || policySet.isEmpty();
    }

    protected static void addAdditionalStoreFromLocation(String location, ExtendedPKIXParameters pkixParams) {
        if (pkixParams.isAdditionalLocationsEnabled()) {
            try {
                if (location.startsWith("ldap://")) {
                    String url;
                    location = location.substring(7);
                    String base = null;
                    if (location.indexOf("/") != -1) {
                        base = location.substring(location.indexOf("/"));
                        url = "ldap://" + location.substring(0, location.indexOf("/"));
                    } else {
                        url = "ldap://" + location;
                    }
                    X509StoreParameters params = new Builder(url, base).build();
                    pkixParams.addAdditionalStore(X509Store.getInstance("CERTIFICATE/LDAP", params, BouncyCastleProvider.PROVIDER_NAME));
                    pkixParams.addAdditionalStore(X509Store.getInstance("CRL/LDAP", params, BouncyCastleProvider.PROVIDER_NAME));
                    pkixParams.addAdditionalStore(X509Store.getInstance("ATTRIBUTECERTIFICATE/LDAP", params, BouncyCastleProvider.PROVIDER_NAME));
                    pkixParams.addAdditionalStore(X509Store.getInstance("CERTIFICATEPAIR/LDAP", params, BouncyCastleProvider.PROVIDER_NAME));
                }
            } catch (Exception e) {
                throw new RuntimeException("Exception adding X.509 stores.");
            }
        }
    }

    protected static Collection findCertificates(X509CertStoreSelector certSelect, List certStores) throws AnnotatedException {
        Set certs = new HashSet();
        for (X509Store obj : certStores) {
            if (obj instanceof X509Store) {
                try {
                    certs.addAll(obj.getMatches(certSelect));
                } catch (StoreException e) {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
                }
            }
            try {
                certs.addAll(((CertStore) obj).getCertificates(certSelect));
            } catch (CertStoreException e2) {
                throw new AnnotatedException("Problem while picking certificates from certificate store.", e2);
            }
        }
        return certs;
    }

    protected static Collection findCertificates(X509AttributeCertStoreSelector certSelect, List certStores) throws AnnotatedException {
        Set certs = new HashSet();
        for (X509Store obj : certStores) {
            if (obj instanceof X509Store) {
                try {
                    certs.addAll(obj.getMatches(certSelect));
                } catch (StoreException e) {
                    throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
                }
            }
        }
        return certs;
    }

    protected static void addAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp, ExtendedPKIXParameters pkixParams) throws AnnotatedException {
        if (crldp != null) {
            try {
                DistributionPoint[] dps = crldp.getDistributionPoints();
                for (DistributionPoint distributionPoint : dps) {
                    DistributionPointName dpn = distributionPoint.getDistributionPoint();
                    if (dpn != null && dpn.getType() == 0) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        for (int j = 0; j < genNames.length; j++) {
                            if (genNames[j].getTagNo() == 6) {
                                addAdditionalStoreFromLocation(DERIA5String.getInstance(genNames[j].getName()).getString(), pkixParams);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                throw new AnnotatedException("Distribution points could not be read.", e);
            }
        }
    }

    protected static void getCRLIssuersFromDistributionPoint(DistributionPoint dp, Collection issuerPrincipals, X509CRLSelector selector, ExtendedPKIXParameters pkixParams) throws AnnotatedException {
        List<X500Principal> issuers = new ArrayList();
        if (dp.getCRLIssuer() != null) {
            GeneralName[] genNames = dp.getCRLIssuer().getNames();
            for (int j = 0; j < genNames.length; j++) {
                if (genNames[j].getTagNo() == 4) {
                    try {
                        issuers.add(new X500Principal(genNames[j].getName().getDERObject().getEncoded()));
                    } catch (IOException e) {
                        throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", e);
                    }
                }
            }
        } else if (dp.getDistributionPoint() == null) {
            throw new AnnotatedException("CRL issuer is omitted from distribution point but no distributionPoint field present.");
        } else {
            for (X500Principal add : issuerPrincipals) {
                issuers.add(add);
            }
        }
        for (X500Principal add2 : issuers) {
            try {
                selector.addIssuerName(add2.getEncoded());
            } catch (IOException ex) {
                throw new AnnotatedException("Cannot decode CRL issuer information.", ex);
            }
        }
    }

    private static BigInteger getSerialNumber(Object cert) {
        if (cert instanceof X509Certificate) {
            return ((X509Certificate) cert).getSerialNumber();
        }
        return ((X509AttributeCertificate) cert).getSerialNumber();
    }

    protected static void getCertStatus(Date validDate, X509CRL crl, Object cert, CertStatus certStatus) throws AnnotatedException {
        try {
            X509CRLEntryObject crl_entry = (X509CRLEntryObject) new X509CRLObject(new CertificateList((ASN1Sequence) ASN1Object.fromByteArray(crl.getEncoded()))).getRevokedCertificate(getSerialNumber(cert));
            if (crl_entry == null) {
                return;
            }
            if (getEncodedIssuerPrincipal(cert).equals(crl_entry.getCertificateIssuer()) || getEncodedIssuerPrincipal(cert).equals(getIssuerPrincipal(crl))) {
                DEREnumerated reasonCode = null;
                if (crl_entry.hasExtensions()) {
                    try {
                        reasonCode = DEREnumerated.getInstance(getExtensionValue(crl_entry, X509Extensions.ReasonCode.getId()));
                    } catch (Exception e) {
                        AnnotatedException annotatedException = new AnnotatedException("Reason code CRL entry extension could not be decoded.", e);
                    }
                }
                if (validDate.getTime() >= crl_entry.getRevocationDate().getTime() || reasonCode == null || reasonCode.getValue().intValue() == 0 || reasonCode.getValue().intValue() == 1 || reasonCode.getValue().intValue() == 2 || reasonCode.getValue().intValue() == 8) {
                    if (reasonCode != null) {
                        certStatus.setCertStatus(reasonCode.getValue().intValue());
                    } else {
                        certStatus.setCertStatus(0);
                    }
                    certStatus.setRevocationDate(crl_entry.getRevocationDate());
                }
            }
        } catch (Exception exception) {
            throw new AnnotatedException("Bouncy Castle X509CRLObject could not be created.", exception);
        }
    }

    protected static Set getDeltaCRLs(Date currentDate, ExtendedPKIXParameters paramsPKIX, X509CRL completeCRL) throws AnnotatedException {
        X509CRLStoreSelector deltaSelect = new X509CRLStoreSelector();
        try {
            deltaSelect.addIssuerName(getIssuerPrincipal(completeCRL).getEncoded());
        } catch (IOException e) {
            AnnotatedException annotatedException = new AnnotatedException("Cannot extract issuer from CRL.", e);
        }
        BigInteger completeCRLNumber = null;
        try {
            DERObject derObject = getExtensionValue(completeCRL, CRL_NUMBER);
            if (derObject != null) {
                completeCRLNumber = DERInteger.getInstance(derObject).getPositiveValue();
            }
            try {
                BigInteger bigInteger;
                byte[] idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
                if (completeCRLNumber == null) {
                    bigInteger = null;
                } else {
                    bigInteger = completeCRLNumber.add(BigInteger.valueOf(1));
                }
                deltaSelect.setMinCRLNumber(bigInteger);
                deltaSelect.setIssuingDistributionPoint(idp);
                deltaSelect.setIssuingDistributionPointEnabled(true);
                deltaSelect.setMaxBaseCRLNumber(completeCRLNumber);
                Set<X509CRL> temp = CRL_UTIL.findCRLs(deltaSelect, paramsPKIX, currentDate);
                Set result = new HashSet();
                for (X509CRL crl : temp) {
                    if (isDeltaCRL(crl)) {
                        result.add(crl);
                    }
                }
                return result;
            } catch (Exception e2) {
                throw new AnnotatedException("Issuing distribution point extension value could not be read.", e2);
            }
        } catch (Exception e22) {
            throw new AnnotatedException("CRL number extension could not be extracted from CRL.", e22);
        }
    }

    private static boolean isDeltaCRL(X509CRL crl) {
        return crl.getCriticalExtensionOIDs().contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
    }

    protected static Set getCompleteCRLs(DistributionPoint dp, Object cert, Date currentDate, ExtendedPKIXParameters paramsPKIX) throws AnnotatedException {
        X509CRLStoreSelector crlselect = new X509CRLStoreSelector();
        try {
            Set issuers = new HashSet();
            if (cert instanceof X509AttributeCertificate) {
                issuers.add(((X509AttributeCertificate) cert).getIssuer().getPrincipals()[0]);
            } else {
                issuers.add(getEncodedIssuerPrincipal(cert));
            }
            getCRLIssuersFromDistributionPoint(dp, issuers, crlselect, paramsPKIX);
        } catch (AnnotatedException e) {
            AnnotatedException annotatedException = new AnnotatedException("Could not get issuer information from distribution point.", e);
        }
        if (cert instanceof X509Certificate) {
            crlselect.setCertificateChecking((X509Certificate) cert);
        } else if (cert instanceof X509AttributeCertificate) {
            crlselect.setAttrCertificateChecking((X509AttributeCertificate) cert);
        }
        crlselect.setCompleteCRLEnabled(true);
        Set crls = CRL_UTIL.findCRLs(crlselect, paramsPKIX, currentDate);
        if (!crls.isEmpty()) {
            return crls;
        }
        if (cert instanceof X509AttributeCertificate) {
            throw new AnnotatedException("No CRLs found for issuer \"" + ((X509AttributeCertificate) cert).getIssuer().getPrincipals()[0] + "\"");
        }
        throw new AnnotatedException("No CRLs found for issuer \"" + ((X509Certificate) cert).getIssuerX500Principal() + "\"");
    }

    protected static Date getValidCertDateFromValidityModel(ExtendedPKIXParameters paramsPKIX, CertPath certPath, int index) throws AnnotatedException {
        if (paramsPKIX.getValidityModel() != 1) {
            return getValidDate(paramsPKIX);
        }
        if (index <= 0) {
            return getValidDate(paramsPKIX);
        }
        if (index - 1 != 0) {
            return ((X509Certificate) certPath.getCertificates().get(index - 1)).getNotBefore();
        }
        DERGeneralizedTime dateOfCertgen = null;
        try {
            byte[] extBytes = ((X509Certificate) certPath.getCertificates().get(index - 1)).getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen.getId());
            if (extBytes != null) {
                dateOfCertgen = DERGeneralizedTime.getInstance(ASN1Object.fromByteArray(extBytes));
            }
            if (dateOfCertgen == null) {
                return ((X509Certificate) certPath.getCertificates().get(index - 1)).getNotBefore();
            }
            try {
                return dateOfCertgen.getDate();
            } catch (ParseException e) {
                throw new AnnotatedException("Date from date of cert gen extension could not be parsed.", e);
            }
        } catch (IOException e2) {
            throw new AnnotatedException("Date of cert gen extension could not be read.");
        } catch (IllegalArgumentException e3) {
            throw new AnnotatedException("Date of cert gen extension could not be read.");
        }
    }

    protected static PublicKey getNextWorkingKey(List certs, int index) throws CertPathValidatorException {
        PublicKey pubKey = ((Certificate) certs.get(index)).getPublicKey();
        if (!(pubKey instanceof DSAPublicKey)) {
            return pubKey;
        }
        DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
        if (dsaPubKey.getParams() != null) {
            return dsaPubKey;
        }
        int i = index + 1;
        while (i < certs.size()) {
            pubKey = ((X509Certificate) certs.get(i)).getPublicKey();
            if (pubKey instanceof DSAPublicKey) {
                DSAPublicKey prevDSAPubKey = (DSAPublicKey) pubKey;
                if (prevDSAPubKey.getParams() == null) {
                    i++;
                } else {
                    DSAParams dsaParams = prevDSAPubKey.getParams();
                    try {
                        return KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME).generatePublic(new DSAPublicKeySpec(dsaPubKey.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));
                    } catch (Exception exception) {
                        throw new RuntimeException(exception.getMessage());
                    }
                }
            }
            throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
        }
        throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
    }

    protected static Collection findIssuerCerts(X509Certificate cert, ExtendedPKIXBuilderParameters pkixParams) throws AnnotatedException {
        X509CertStoreSelector certSelect = new X509CertStoreSelector();
        Set certs = new HashSet();
        try {
            certSelect.setSubject(cert.getIssuerX500Principal().getEncoded());
            try {
                List<X509Certificate> matches = new ArrayList();
                matches.addAll(findCertificates(certSelect, pkixParams.getCertStores()));
                matches.addAll(findCertificates(certSelect, pkixParams.getStores()));
                matches.addAll(findCertificates(certSelect, pkixParams.getAdditionalStores()));
                for (X509Certificate issuer : matches) {
                    certs.add(issuer);
                }
                return certs;
            } catch (AnnotatedException e) {
                throw new AnnotatedException("Issuer certificate cannot be searched.", e);
            }
        } catch (IOException ex) {
            throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
        }
    }

    protected static void verifyX509Certificate(X509Certificate cert, PublicKey publicKey, String sigProvider) throws GeneralSecurityException {
        if (sigProvider == null) {
            cert.verify(publicKey);
        } else {
            cert.verify(publicKey, sigProvider);
        }
    }
}
