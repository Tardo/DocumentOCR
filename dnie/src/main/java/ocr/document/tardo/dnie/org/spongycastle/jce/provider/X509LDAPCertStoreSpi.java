package org.spongycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.x509.CertificatePair;
import org.spongycastle.jce.X509LDAPCertStoreParameters;

public class X509LDAPCertStoreSpi extends CertStoreSpi {
    private static String LDAP_PROVIDER = "com.sun.jndi.ldap.LdapCtxFactory";
    private static String REFERRALS_IGNORE = "ignore";
    private static final String SEARCH_SECURITY_LEVEL = "none";
    private static final String URL_CONTEXT_PREFIX = "com.sun.jndi.url";
    private X509LDAPCertStoreParameters params;

    public X509LDAPCertStoreSpi(CertStoreParameters params) throws InvalidAlgorithmParameterException {
        super(params);
        if (params instanceof X509LDAPCertStoreParameters) {
            this.params = (X509LDAPCertStoreParameters) params;
            return;
        }
        throw new InvalidAlgorithmParameterException(X509LDAPCertStoreSpi.class.getName() + ": parameter must be a " + X509LDAPCertStoreParameters.class.getName() + " object\n" + params.toString());
    }

    private DirContext connectLDAP() throws NamingException {
        Properties props = new Properties();
        props.setProperty("java.naming.factory.initial", LDAP_PROVIDER);
        props.setProperty("java.naming.batchsize", "0");
        props.setProperty("java.naming.provider.url", this.params.getLdapURL());
        props.setProperty("java.naming.factory.url.pkgs", URL_CONTEXT_PREFIX);
        props.setProperty("java.naming.referral", REFERRALS_IGNORE);
        props.setProperty("java.naming.security.authentication", SEARCH_SECURITY_LEVEL);
        return new InitialDirContext(props);
    }

    private String parseDN(String subject, String subjectAttributeName) {
        String temp = subject;
        temp = temp.substring(subjectAttributeName.length() + temp.toLowerCase().indexOf(subjectAttributeName.toLowerCase()));
        int end = temp.indexOf(44);
        if (end == -1) {
            end = temp.length();
        }
        while (temp.charAt(end - 1) == '\\') {
            end = temp.indexOf(44, end + 1);
            if (end == -1) {
                end = temp.length();
            }
        }
        temp = temp.substring(0, end);
        temp = temp.substring(temp.indexOf(61) + 1);
        if (temp.charAt(0) == ' ') {
            temp = temp.substring(1);
        }
        if (temp.startsWith("\"")) {
            temp = temp.substring(1);
        }
        if (temp.endsWith("\"")) {
            return temp.substring(0, temp.length() - 1);
        }
        return temp;
    }

    public Collection engineGetCertificates(CertSelector selector) throws CertStoreException {
        if (selector instanceof X509CertSelector) {
            X509CertSelector xselector = (X509CertSelector) selector;
            Set certSet = new HashSet();
            Set<byte[]> set = getEndCertificates(xselector);
            set.addAll(getCACertificates(xselector));
            set.addAll(getCrossCertificates(xselector));
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                for (byte[] bytes : set) {
                    if (!(bytes == null || bytes.length == 0)) {
                        List<byte[]> bytesList = new ArrayList();
                        bytesList.add(bytes);
                        try {
                            CertificatePair pair = CertificatePair.getInstance(new ASN1InputStream(bytes).readObject());
                            bytesList.clear();
                            if (pair.getForward() != null) {
                                bytesList.add(pair.getForward().getEncoded());
                            }
                            if (pair.getReverse() != null) {
                                bytesList.add(pair.getReverse().getEncoded());
                            }
                        } catch (IOException e) {
                        } catch (IllegalArgumentException e2) {
                        }
                        for (byte[] byteArrayInputStream : bytesList) {
                            try {
                                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(byteArrayInputStream));
                                if (xselector.match(cert)) {
                                    certSet.add(cert);
                                }
                            } catch (Exception e3) {
                            }
                        }
                    }
                }
                return certSet;
            } catch (Exception e4) {
                throw new CertStoreException("certificate cannot be constructed from LDAP result: " + e4);
            }
        }
        throw new CertStoreException("selector is not a X509CertSelector");
    }

    private Set certSubjectSerialSearch(X509CertSelector xselector, String[] attrs, String attrName, String subjectAttributeName) throws CertStoreException {
        Set set = new HashSet();
        try {
            if (xselector.getSubjectAsBytes() == null && xselector.getSubjectAsString() == null && xselector.getCertificate() == null) {
                set.addAll(search(attrName, "*", attrs));
            } else {
                String subject;
                String serial = null;
                if (xselector.getCertificate() != null) {
                    subject = xselector.getCertificate().getSubjectX500Principal().getName("RFC1779");
                    serial = xselector.getCertificate().getSerialNumber().toString();
                } else if (xselector.getSubjectAsBytes() != null) {
                    subject = new X500Principal(xselector.getSubjectAsBytes()).getName("RFC1779");
                } else {
                    subject = xselector.getSubjectAsString();
                }
                set.addAll(search(attrName, "*" + parseDN(subject, subjectAttributeName) + "*", attrs));
                if (!(serial == null || this.params.getSearchForSerialNumberIn() == null)) {
                    set.addAll(search(this.params.getSearchForSerialNumberIn(), "*" + serial + "*", attrs));
                }
            }
            return set;
        } catch (IOException e) {
            throw new CertStoreException("exception processing selector: " + e);
        }
    }

    private Set getEndCertificates(X509CertSelector xselector) throws CertStoreException {
        return certSubjectSerialSearch(xselector, new String[]{this.params.getUserCertificateAttribute()}, this.params.getLdapUserCertificateAttributeName(), this.params.getUserCertificateSubjectAttributeName());
    }

    private Set getCACertificates(X509CertSelector xselector) throws CertStoreException {
        String[] attrs = new String[]{this.params.getCACertificateAttribute()};
        Set set = certSubjectSerialSearch(xselector, attrs, this.params.getLdapCACertificateAttributeName(), this.params.getCACertificateSubjectAttributeName());
        if (set.isEmpty()) {
            set.addAll(search(null, "*", attrs));
        }
        return set;
    }

    private Set getCrossCertificates(X509CertSelector xselector) throws CertStoreException {
        String[] attrs = new String[]{this.params.getCrossCertificateAttribute()};
        Set set = certSubjectSerialSearch(xselector, attrs, this.params.getLdapCrossCertificateAttributeName(), this.params.getCrossCertificateSubjectAttributeName());
        if (set.isEmpty()) {
            set.addAll(search(null, "*", attrs));
        }
        return set;
    }

    public Collection engineGetCRLs(CRLSelector selector) throws CertStoreException {
        String[] attrs = new String[]{this.params.getCertificateRevocationListAttribute()};
        if (selector instanceof X509CRLSelector) {
            X509CRLSelector xselector = (X509CRLSelector) selector;
            Set crlSet = new HashSet();
            String attrName = this.params.getLdapCertificateRevocationListAttributeName();
            Set<byte[]> set = new HashSet();
            if (xselector.getIssuerNames() != null) {
                for (Object o : xselector.getIssuerNames()) {
                    String attrValue;
                    if (o instanceof String) {
                        attrValue = parseDN((String) o, this.params.getCertificateRevocationListIssuerAttributeName());
                    } else {
                        attrValue = parseDN(new X500Principal((byte[]) o).getName("RFC1779"), this.params.getCertificateRevocationListIssuerAttributeName());
                    }
                    set.addAll(search(attrName, "*" + attrValue + "*", attrs));
                }
            } else {
                set.addAll(search(attrName, "*", attrs));
            }
            set.addAll(search(null, "*", attrs));
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                for (byte[] byteArrayInputStream : set) {
                    CRL crl = cf.generateCRL(new ByteArrayInputStream(byteArrayInputStream));
                    if (xselector.match(crl)) {
                        crlSet.add(crl);
                    }
                }
                return crlSet;
            } catch (Exception e) {
                throw new CertStoreException("CRL cannot be constructed from LDAP result " + e);
            }
        }
        throw new CertStoreException("selector is not a X509CRLSelector");
    }

    private Set search(String attributeName, String attributeValue, String[] attrs) throws CertStoreException {
        String filter = attributeName + "=" + attributeValue;
        if (attributeName == null) {
            filter = null;
        }
        DirContext ctx = null;
        Set set = new HashSet();
        try {
            ctx = connectLDAP();
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(2);
            constraints.setCountLimit(0);
            for (int i = 0; i < attrs.length; i++) {
                String[] temp = new String[]{attrs[i]};
                constraints.setReturningAttributes(temp);
                String filter2 = "(&(" + filter + ")(" + temp[0] + "=*))";
                if (filter == null) {
                    filter2 = "(" + temp[0] + "=*)";
                }
                NamingEnumeration results = ctx.search(this.params.getBaseDN(), filter2, constraints);
                while (results.hasMoreElements()) {
                    NamingEnumeration enumeration = ((Attribute) ((SearchResult) results.next()).getAttributes().getAll().next()).getAll();
                    while (enumeration.hasMore()) {
                        set.add(enumeration.next());
                    }
                }
            }
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception e) {
                }
            }
            return set;
        } catch (Exception e2) {
            throw new CertStoreException("Error getting results from LDAP directory " + e2);
        } catch (Throwable th) {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception e3) {
                }
            }
        }
    }
}
