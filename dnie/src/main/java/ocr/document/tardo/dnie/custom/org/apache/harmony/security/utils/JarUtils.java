package custom.org.apache.harmony.security.utils;

import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.pkcs7.ContentInfo;
import custom.org.apache.harmony.security.pkcs7.SignedData;
import custom.org.apache.harmony.security.pkcs7.SignerInfo;
import custom.org.apache.harmony.security.provider.cert.X509CertImpl;
import custom.org.apache.harmony.security.x501.AttributeTypeAndValue;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.security.auth.x500.X500Principal;

public class JarUtils {
    private static final int[] MESSAGE_DIGEST_OID = new int[]{1, 2, 840, 113549, 1, 9, 4};

    public static Certificate[] verifySignature(InputStream signature, InputStream signatureBlock) throws IOException, GeneralSecurityException {
        SignedData signedData = ((ContentInfo) ContentInfo.ASN1.decode(new BerInputStream(signatureBlock))).getSignedData();
        if (signedData == null) {
            throw new IOException(Messages.getString("security.173"));
        }
        Collection<custom.org.apache.harmony.security.x509.Certificate> encCerts = signedData.getCertificates();
        if (encCerts.isEmpty()) {
            return null;
        }
        X509Certificate[] certs = new X509Certificate[encCerts.size()];
        int i = 0;
        for (custom.org.apache.harmony.security.x509.Certificate x509CertImpl : encCerts) {
            int i2 = i + 1;
            certs[i] = new X509CertImpl(x509CertImpl);
            i = i2;
        }
        List sigInfos = signedData.getSignerInfos();
        if (sigInfos.isEmpty()) {
            return null;
        }
        SignerInfo sigInfo = (SignerInfo) sigInfos.get(0);
        X500Principal issuer = sigInfo.getIssuer();
        BigInteger snum = sigInfo.getSerialNumber();
        int issuerSertIndex = 0;
        i = 0;
        while (i < certs.length) {
            if (issuer.equals(certs[i].getIssuerDN()) && snum.equals(certs[i].getSerialNumber())) {
                issuerSertIndex = i;
                break;
            }
            i++;
        }
        if (i == certs.length) {
            return null;
        }
        if (certs[issuerSertIndex].hasUnsupportedCriticalExtension()) {
            throw new SecurityException(Messages.getString("security.174"));
        }
        Signature sig = null;
        String da = sigInfo.getdigestAlgorithm();
        String dea = sigInfo.getDigestEncryptionAlgorithm();
        if (!(da == null || dea == null)) {
            try {
                sig = Signature.getInstance(da + "with" + dea);
            } catch (NoSuchAlgorithmException e) {
            }
        }
        if (sig == null) {
            String alg = da;
            if (alg == null) {
                return null;
            }
            try {
                sig = Signature.getInstance(alg);
            } catch (NoSuchAlgorithmException e2) {
                return null;
            }
        }
        sig.initVerify(certs[issuerSertIndex]);
        List<AttributeTypeAndValue> atr = sigInfo.getAuthenticatedAttributes();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while (true) {
            int numRead = signature.read();
            if (numRead == -1) {
                break;
            }
            baos.write((byte) numRead);
        }
        signature.close();
        byte[] sfBytes = baos.toByteArray();
        if (atr == null) {
            sig.update(sfBytes);
        } else {
            sig.update(sigInfo.getEncodedAuthenticatedAttributes());
            for (AttributeTypeAndValue a : atr) {
                if (Arrays.equals(a.getType().getOid(), MESSAGE_DIGEST_OID)) {
                }
            }
            if (!(null == null || Arrays.equals(null, MessageDigest.getInstance(sigInfo.getDigestAlgorithm()).digest(sfBytes)))) {
                throw new SecurityException(Messages.getString("security.175"));
            }
        }
        if (sig.verify(sigInfo.getEncryptedDigest())) {
            return createChain(certs[issuerSertIndex], certs);
        }
        throw new SecurityException(Messages.getString("security.176"));
    }

    private static X509Certificate[] createChain(X509Certificate signer, X509Certificate[] candidates) {
        LinkedList chain = new LinkedList();
        chain.add(0, signer);
        if (signer.getSubjectDN().equals(signer.getIssuerDN())) {
            return (X509Certificate[]) chain.toArray(new X509Certificate[1]);
        }
        Principal issuer = signer.getIssuerDN();
        int count = 1;
        while (true) {
            X509Certificate issuerCert = findCert(issuer, candidates);
            if (issuerCert != null) {
                chain.add(issuerCert);
                count++;
                if (issuerCert.getSubjectDN().equals(issuerCert.getIssuerDN())) {
                    break;
                }
                issuer = issuerCert.getIssuerDN();
            } else {
                break;
            }
        }
        return (X509Certificate[]) chain.toArray(new X509Certificate[count]);
    }

    private static X509Certificate findCert(Principal issuer, X509Certificate[] candidates) {
        for (int i = 0; i < candidates.length; i++) {
            if (issuer.equals(candidates[i].getSubjectDN())) {
                return candidates[i];
            }
        }
        return null;
    }
}
