package org.bouncycastle.cert;

import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DigestCalculator;

public class X509ExtensionUtils {
    private DigestCalculator calculator;

    public X509ExtensionUtils(DigestCalculator digestCalculator) {
        this.calculator = digestCalculator;
    }

    private byte[] calculateIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        byte[] bytes = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        OutputStream outputStream = this.calculator.getOutputStream();
        try {
            outputStream.write(bytes);
            outputStream.close();
            return this.calculator.getDigest();
        } catch (Throwable e) {
            throw new CertRuntimeException("unable to calculate identifier: " + e.getMessage(), e);
        }
    }

    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        return new AuthorityKeyIdentifier(calculateIdentifier(subjectPublicKeyInfo));
    }

    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(X509CertificateHolder x509CertificateHolder) {
        if (x509CertificateHolder.getVersionNumber() != 3) {
            return new AuthorityKeyIdentifier(calculateIdentifier(x509CertificateHolder.getSubjectPublicKeyInfo()), new GeneralNames(new GeneralName(x509CertificateHolder.getIssuer())), x509CertificateHolder.getSerialNumber());
        }
        GeneralName generalName = new GeneralName(x509CertificateHolder.getIssuer());
        Extension extension = x509CertificateHolder.getExtension(Extension.subjectKeyIdentifier);
        return extension != null ? new AuthorityKeyIdentifier(ASN1OctetString.getInstance(extension.getParsedValue()).getOctets(), new GeneralNames(generalName), x509CertificateHolder.getSerialNumber()) : new AuthorityKeyIdentifier(calculateIdentifier(x509CertificateHolder.getSubjectPublicKeyInfo()), new GeneralNames(generalName), x509CertificateHolder.getSerialNumber());
    }

    public SubjectKeyIdentifier createSubjectKeyIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        return new SubjectKeyIdentifier(calculateIdentifier(subjectPublicKeyInfo));
    }

    public SubjectKeyIdentifier createTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        Object calculateIdentifier = calculateIdentifier(subjectPublicKeyInfo);
        byte[] bArr = new byte[8];
        System.arraycopy(calculateIdentifier, calculateIdentifier.length - 8, bArr, 0, bArr.length);
        bArr[0] = (byte) (bArr[0] & 15);
        bArr[0] = (byte) (bArr[0] | 64);
        return new SubjectKeyIdentifier(bArr);
    }
}
