package org.bouncycastle.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2ParameterSpec;
import org.bouncycastle.util.Integers;

public class TSPUtil {
    private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());
    private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
    private static final Map digestLengths = new HashMap();
    private static final Map digestNames = new HashMap();

    static {
        digestLengths.put(PKCSObjectIdentifiers.md5.getId(), Integers.valueOf(16));
        digestLengths.put(OIWObjectIdentifiers.idSHA1.getId(), Integers.valueOf(20));
        digestLengths.put(NISTObjectIdentifiers.id_sha224.getId(), Integers.valueOf(28));
        digestLengths.put(NISTObjectIdentifiers.id_sha256.getId(), Integers.valueOf(32));
        digestLengths.put(NISTObjectIdentifiers.id_sha384.getId(), Integers.valueOf(48));
        digestLengths.put(NISTObjectIdentifiers.id_sha512.getId(), Integers.valueOf(64));
        digestLengths.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), Integers.valueOf(16));
        digestLengths.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), Integers.valueOf(20));
        digestLengths.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), Integers.valueOf(32));
        digestLengths.put(CryptoProObjectIdentifiers.gostR3411.getId(), Integers.valueOf(32));
        digestNames.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
        digestNames.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
        digestNames.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
        digestNames.put(NISTObjectIdentifiers.id_sha256.getId(), McElieceCCA2ParameterSpec.DEFAULT_MD);
        digestNames.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
        digestNames.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
        digestNames.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
        digestNames.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
        digestNames.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), McElieceCCA2ParameterSpec.DEFAULT_MD);
        digestNames.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
        digestNames.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
        digestNames.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
        digestNames.put(CryptoProObjectIdentifiers.gostR3411.getId(), "GOST3411");
    }

    static void addExtension(ExtensionsGenerator extensionsGenerator, ASN1ObjectIdentifier aSN1ObjectIdentifier, boolean z, ASN1Encodable aSN1Encodable) throws TSPIOException {
        try {
            extensionsGenerator.addExtension(aSN1ObjectIdentifier, z, aSN1Encodable);
        } catch (Throwable e) {
            throw new TSPIOException("cannot encode extension: " + e.getMessage(), e);
        }
    }

    static MessageDigest createDigestInstance(String str, Provider provider) throws NoSuchAlgorithmException {
        String digestAlgName = getDigestAlgName(str);
        if (provider != null) {
            try {
                return MessageDigest.getInstance(digestAlgName, provider);
            } catch (NoSuchAlgorithmException e) {
            }
        }
        return MessageDigest.getInstance(digestAlgName);
    }

    static Set getCriticalExtensionOIDs(X509Extensions x509Extensions) {
        return x509Extensions == null ? EMPTY_SET : Collections.unmodifiableSet(new HashSet(Arrays.asList(x509Extensions.getCriticalExtensionOIDs())));
    }

    static String getDigestAlgName(String str) {
        String str2 = (String) digestNames.get(str);
        return str2 != null ? str2 : str;
    }

    static int getDigestLength(String str) throws TSPException {
        Integer num = (Integer) digestLengths.get(str);
        if (num != null) {
            return num.intValue();
        }
        throw new TSPException("digest algorithm cannot be found.");
    }

    static List getExtensionOIDs(Extensions extensions) {
        return extensions == null ? EMPTY_LIST : Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
    }

    static Set getNonCriticalExtensionOIDs(X509Extensions x509Extensions) {
        return x509Extensions == null ? EMPTY_SET : Collections.unmodifiableSet(new HashSet(Arrays.asList(x509Extensions.getNonCriticalExtensionOIDs())));
    }

    public static Collection getSignatureTimestamps(SignerInformation signerInformation, Provider provider) throws TSPValidationException {
        Collection arrayList = new ArrayList();
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            ASN1EncodableVector all = unsignedAttributes.getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            for (int i = 0; i < all.size(); i++) {
                ASN1Set attrValues = ((Attribute) all.get(i)).getAttrValues();
                int i2 = 0;
                while (i2 < attrValues.size()) {
                    try {
                        TimeStampToken timeStampToken = new TimeStampToken(ContentInfo.getInstance(attrValues.getObjectAt(i2)));
                        TimeStampTokenInfo timeStampInfo = timeStampToken.getTimeStampInfo();
                        if (org.bouncycastle.util.Arrays.constantTimeAreEqual(createDigestInstance(timeStampInfo.getMessageImprintAlgOID().getId(), provider).digest(signerInformation.getSignature()), timeStampInfo.getMessageImprintDigest())) {
                            arrayList.add(timeStampToken);
                            i2++;
                        } else {
                            throw new TSPValidationException("Incorrect digest in message imprint");
                        }
                    } catch (NoSuchAlgorithmException e) {
                        throw new TSPValidationException("Unknown hash algorithm specified in timestamp");
                    } catch (Exception e2) {
                        throw new TSPValidationException("Timestamp could not be parsed");
                    }
                }
            }
        }
        return arrayList;
    }

    public static Collection getSignatureTimestamps(SignerInformation signerInformation, DigestCalculatorProvider digestCalculatorProvider) throws TSPValidationException {
        Collection arrayList = new ArrayList();
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            ASN1EncodableVector all = unsignedAttributes.getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            for (int i = 0; i < all.size(); i++) {
                ASN1Set attrValues = ((Attribute) all.get(i)).getAttrValues();
                int i2 = 0;
                while (i2 < attrValues.size()) {
                    try {
                        TimeStampToken timeStampToken = new TimeStampToken(ContentInfo.getInstance(attrValues.getObjectAt(i2)));
                        TimeStampTokenInfo timeStampInfo = timeStampToken.getTimeStampInfo();
                        DigestCalculator digestCalculator = digestCalculatorProvider.get(timeStampInfo.getHashAlgorithm());
                        OutputStream outputStream = digestCalculator.getOutputStream();
                        outputStream.write(signerInformation.getSignature());
                        outputStream.close();
                        if (org.bouncycastle.util.Arrays.constantTimeAreEqual(digestCalculator.getDigest(), timeStampInfo.getMessageImprintDigest())) {
                            arrayList.add(timeStampToken);
                            i2++;
                        } else {
                            throw new TSPValidationException("Incorrect digest in message imprint");
                        }
                    } catch (OperatorCreationException e) {
                        throw new TSPValidationException("Unknown hash algorithm specified in timestamp");
                    } catch (Exception e2) {
                        throw new TSPValidationException("Timestamp could not be parsed");
                    }
                }
            }
        }
        return arrayList;
    }

    public static void validateCertificate(X509Certificate x509Certificate) throws TSPValidationException {
        if (x509Certificate.getVersion() != 3) {
            throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
        }
        byte[] extensionValue = x509Certificate.getExtensionValue(X509Extensions.ExtendedKeyUsage.getId());
        if (extensionValue == null) {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
        } else if (x509Certificate.getCriticalExtensionOIDs().contains(X509Extensions.ExtendedKeyUsage.getId())) {
            try {
                ExtendedKeyUsage instance = ExtendedKeyUsage.getInstance(new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString) new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject()).getOctets())).readObject());
                if (!instance.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || instance.size() != 1) {
                    throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
                }
            } catch (IOException e) {
                throw new TSPValidationException("cannot process ExtendedKeyUsage extension");
            }
        } else {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
        }
    }

    public static void validateCertificate(X509CertificateHolder x509CertificateHolder) throws TSPValidationException {
        if (x509CertificateHolder.toASN1Structure().getVersionNumber() != 3) {
            throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
        }
        Extension extension = x509CertificateHolder.getExtension(Extension.extendedKeyUsage);
        if (extension == null) {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
        } else if (extension.isCritical()) {
            ExtendedKeyUsage instance = ExtendedKeyUsage.getInstance(extension.getParsedValue());
            if (!instance.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || instance.size() != 1) {
                throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
            }
        } else {
            throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
        }
    }
}
