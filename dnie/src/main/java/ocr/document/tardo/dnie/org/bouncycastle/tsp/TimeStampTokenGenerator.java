package org.bouncycastle.tsp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class TimeStampTokenGenerator {
    int accuracyMicros;
    int accuracyMillis;
    int accuracySeconds;
    private List attrCerts;
    X509Certificate cert;
    private List certs;
    private List crls;
    String digestOID;
    PrivateKey key;
    boolean ordering;
    AttributeTable signedAttr;
    private SignerInfoGenerator signerInfoGen;
    GeneralName tsa;
    private ASN1ObjectIdentifier tsaPolicyOID;
    AttributeTable unsignedAttr;

    /* renamed from: org.bouncycastle.tsp.TimeStampTokenGenerator$3 */
    class C02053 implements DigestCalculator {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        C02053() {
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        }

        public byte[] getDigest() {
            try {
                return MessageDigest.getInstance("SHA-1").digest(this.bOut.toByteArray());
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("cannot find sha-1: " + e.getMessage());
            }
        }

        public OutputStream getOutputStream() {
            return this.bOut;
        }
    }

    public TimeStampTokenGenerator(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2) throws IllegalArgumentException, TSPException {
        this(privateKey, x509Certificate, str, str2, null, null);
    }

    public TimeStampTokenGenerator(PrivateKey privateKey, X509Certificate x509Certificate, String str, String str2, AttributeTable attributeTable, AttributeTable attributeTable2) throws IllegalArgumentException, TSPException {
        this.accuracySeconds = -1;
        this.accuracyMillis = -1;
        this.accuracyMicros = -1;
        this.ordering = false;
        this.tsa = null;
        this.certs = new ArrayList();
        this.crls = new ArrayList();
        this.attrCerts = new ArrayList();
        this.key = privateKey;
        this.cert = x509Certificate;
        this.digestOID = str;
        this.tsaPolicyOID = new ASN1ObjectIdentifier(str2);
        this.unsignedAttr = attributeTable2;
        Hashtable toHashtable = attributeTable != null ? attributeTable.toHashtable() : new Hashtable();
        TSPUtil.validateCertificate(x509Certificate);
        try {
            toHashtable.put(PKCSObjectIdentifiers.id_aa_signingCertificate, new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(new SigningCertificate(new ESSCertID(MessageDigest.getInstance("SHA-1").digest(x509Certificate.getEncoded()))))));
            this.signedAttr = new AttributeTable(toHashtable);
        } catch (Throwable e) {
            throw new TSPException("Can't find a SHA-1 implementation.", e);
        } catch (Throwable e2) {
            throw new TSPException("Exception processing certificate.", e2);
        }
    }

    public TimeStampTokenGenerator(PrivateKey privateKey, X509Certificate x509Certificate, ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) throws IllegalArgumentException, TSPException {
        this(privateKey, x509Certificate, aSN1ObjectIdentifier.getId(), str, null, null);
    }

    public TimeStampTokenGenerator(SignerInfoGenerator signerInfoGenerator, ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IllegalArgumentException, TSPException {
        this(new C02053(), signerInfoGenerator, aSN1ObjectIdentifier);
    }

    public TimeStampTokenGenerator(final SignerInfoGenerator signerInfoGenerator, DigestCalculator digestCalculator, ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IllegalArgumentException, TSPException {
        this.accuracySeconds = -1;
        this.accuracyMillis = -1;
        this.accuracyMicros = -1;
        this.ordering = false;
        this.tsa = null;
        this.certs = new ArrayList();
        this.crls = new ArrayList();
        this.attrCerts = new ArrayList();
        this.signerInfoGen = signerInfoGenerator;
        this.tsaPolicyOID = aSN1ObjectIdentifier;
        if (signerInfoGenerator.hasAssociatedCertificate()) {
            TSPUtil.validateCertificate(signerInfoGenerator.getAssociatedCertificate());
            try {
                OutputStream outputStream = digestCalculator.getOutputStream();
                outputStream.write(signerInfoGenerator.getAssociatedCertificate().getEncoded());
                outputStream.close();
                if (digestCalculator.getAlgorithmIdentifier().getAlgorithm().equals(OIWObjectIdentifiers.idSHA1)) {
                    final ESSCertID eSSCertID = new ESSCertID(digestCalculator.getDigest());
                    this.signerInfoGen = new SignerInfoGenerator(signerInfoGenerator, new CMSAttributeTableGenerator() {
                        public AttributeTable getAttributes(Map map) throws CMSAttributeTableGenerationException {
                            AttributeTable attributes = signerInfoGenerator.getSignedAttributeTableGenerator().getAttributes(map);
                            return attributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null ? attributes.add(PKCSObjectIdentifiers.id_aa_signingCertificate, new SigningCertificate(eSSCertID)) : attributes;
                        }
                    }, signerInfoGenerator.getUnsignedAttributeTableGenerator());
                    return;
                }
                final ESSCertIDv2 eSSCertIDv2 = new ESSCertIDv2(new AlgorithmIdentifier(digestCalculator.getAlgorithmIdentifier().getAlgorithm()), digestCalculator.getDigest());
                this.signerInfoGen = new SignerInfoGenerator(signerInfoGenerator, new CMSAttributeTableGenerator() {
                    public AttributeTable getAttributes(Map map) throws CMSAttributeTableGenerationException {
                        AttributeTable attributes = signerInfoGenerator.getSignedAttributeTableGenerator().getAttributes(map);
                        return attributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) == null ? attributes.add(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new SigningCertificateV2(eSSCertIDv2)) : attributes;
                    }
                }, signerInfoGenerator.getUnsignedAttributeTableGenerator());
                return;
            } catch (Throwable e) {
                throw new TSPException("Exception processing certificate.", e);
            }
        }
        throw new IllegalArgumentException("SignerInfoGenerator must have an associated certificate");
    }

    public TimeStampTokenGenerator(DigestCalculator digestCalculator, SignerInfoGenerator signerInfoGenerator, ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IllegalArgumentException, TSPException {
        this(signerInfoGenerator, digestCalculator, aSN1ObjectIdentifier);
    }

    private String getSigAlgorithm(PrivateKey privateKey, String str) {
        String str2 = null;
        if ((privateKey instanceof RSAPrivateKey) || "RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            str2 = "RSA";
        } else if ((privateKey instanceof DSAPrivateKey) || "DSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            str2 = "DSA";
        } else if ("ECDSA".equalsIgnoreCase(privateKey.getAlgorithm()) || "EC".equalsIgnoreCase(privateKey.getAlgorithm())) {
            str2 = "ECDSA";
        } else if ((privateKey instanceof GOST3410PrivateKey) || "GOST3410".equalsIgnoreCase(privateKey.getAlgorithm())) {
            str2 = "GOST3410";
        } else if ("ECGOST3410".equalsIgnoreCase(privateKey.getAlgorithm())) {
            str2 = CMSSignedGenerator.ENCRYPTION_ECGOST3410;
        }
        return TSPUtil.getDigestAlgName(str) + "with" + str2;
    }

    public void addAttributeCertificates(Store store) {
        this.attrCerts.addAll(store.getMatches(null));
    }

    public void addCRLs(Store store) {
        this.crls.addAll(store.getMatches(null));
    }

    public void addCertificates(Store store) {
        this.certs.addAll(store.getMatches(null));
    }

    public TimeStampToken generate(TimeStampRequest timeStampRequest, BigInteger bigInteger, Date date) throws TSPException {
        if (this.signerInfoGen == null) {
            throw new IllegalStateException("can only use this method with SignerInfoGenerator constructor");
        }
        Accuracy accuracy;
        MessageImprint messageImprint = new MessageImprint(new AlgorithmIdentifier(timeStampRequest.getMessageImprintAlgOID(), DERNull.INSTANCE), timeStampRequest.getMessageImprintDigest());
        if (this.accuracySeconds > 0 || this.accuracyMillis > 0 || this.accuracyMicros > 0) {
            accuracy = new Accuracy(this.accuracySeconds > 0 ? new ASN1Integer((long) this.accuracySeconds) : null, this.accuracyMillis > 0 ? new ASN1Integer((long) this.accuracyMillis) : null, this.accuracyMicros > 0 ? new ASN1Integer((long) this.accuracyMicros) : null);
        } else {
            accuracy = null;
        }
        ASN1Boolean aSN1Boolean = this.ordering ? new ASN1Boolean(this.ordering) : null;
        ASN1Integer aSN1Integer = timeStampRequest.getNonce() != null ? new ASN1Integer(timeStampRequest.getNonce()) : null;
        ASN1ObjectIdentifier aSN1ObjectIdentifier = this.tsaPolicyOID;
        if (timeStampRequest.getReqPolicy() != null) {
            aSN1ObjectIdentifier = timeStampRequest.getReqPolicy();
        }
        TSTInfo tSTInfo = new TSTInfo(aSN1ObjectIdentifier, messageImprint, new ASN1Integer(bigInteger), new ASN1GeneralizedTime(date), accuracy, aSN1Boolean, aSN1Integer, this.tsa, timeStampRequest.getExtensions());
        try {
            CMSSignedDataGenerator cMSSignedDataGenerator = new CMSSignedDataGenerator();
            if (timeStampRequest.getCertReq()) {
                cMSSignedDataGenerator.addCertificates(new CollectionStore(this.certs));
                cMSSignedDataGenerator.addCRLs(new CollectionStore(this.crls));
                cMSSignedDataGenerator.addAttributeCertificates(new CollectionStore(this.attrCerts));
            } else {
                cMSSignedDataGenerator.addCRLs(new CollectionStore(this.crls));
            }
            cMSSignedDataGenerator.addSignerInfoGenerator(this.signerInfoGen);
            return new TimeStampToken(cMSSignedDataGenerator.generate(new CMSProcessableByteArray(PKCSObjectIdentifiers.id_ct_TSTInfo, tSTInfo.getEncoded("DER")), true));
        } catch (Throwable e) {
            throw new TSPException("Error generating time-stamp token", e);
        } catch (Throwable e2) {
            throw new TSPException("Exception encoding info", e2);
        }
    }

    public TimeStampToken generate(TimeStampRequest timeStampRequest, BigInteger bigInteger, Date date, String str) throws NoSuchAlgorithmException, NoSuchProviderException, TSPException {
        if (this.signerInfoGen == null) {
            try {
                JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(str).build());
                jcaSignerInfoGeneratorBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(this.signedAttr));
                if (this.unsignedAttr != null) {
                    jcaSignerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(this.unsignedAttr));
                }
                this.signerInfoGen = jcaSignerInfoGeneratorBuilder.build(new JcaContentSignerBuilder(getSigAlgorithm(this.key, this.digestOID)).setProvider(str).build(this.key), this.cert);
            } catch (Throwable e) {
                throw new TSPException("Error generating signing operator", e);
            } catch (Throwable e2) {
                throw new TSPException("Error encoding certificate", e2);
            }
        }
        return generate(timeStampRequest, bigInteger, date);
    }

    public void setAccuracyMicros(int i) {
        this.accuracyMicros = i;
    }

    public void setAccuracyMillis(int i) {
        this.accuracyMillis = i;
    }

    public void setAccuracySeconds(int i) {
        this.accuracySeconds = i;
    }

    public void setCertificatesAndCRLs(CertStore certStore) throws CertStoreException, TSPException {
        for (X509Certificate jcaX509CertificateHolder : certStore.getCertificates(null)) {
            try {
                this.certs.add(new JcaX509CertificateHolder(jcaX509CertificateHolder));
            } catch (Throwable e) {
                throw new TSPException("cannot encode certificate: " + e.getMessage(), e);
            }
        }
        for (X509CRL jcaX509CRLHolder : certStore.getCRLs(null)) {
            try {
                this.crls.add(new JcaX509CRLHolder(jcaX509CRLHolder));
            } catch (Throwable e2) {
                throw new TSPException("cannot encode CRL: " + e2.getMessage(), e2);
            }
        }
    }

    public void setOrdering(boolean z) {
        this.ordering = z;
    }

    public void setTSA(GeneralName generalName) {
        this.tsa = generalName;
    }
}
