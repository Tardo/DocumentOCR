package org.bouncycastle.x509.extension;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class SubjectKeyIdentifierStructure extends SubjectKeyIdentifier {
    public SubjectKeyIdentifierStructure(PublicKey publicKey) throws InvalidKeyException {
        super(fromPublicKey(publicKey));
    }

    public SubjectKeyIdentifierStructure(byte[] bArr) throws IOException {
        super((ASN1OctetString) X509ExtensionUtil.fromExtensionValue(bArr));
    }

    private static ASN1OctetString fromPublicKey(PublicKey publicKey) throws InvalidKeyException {
        try {
            return (ASN1OctetString) new SubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())).toASN1Object();
        } catch (Exception e) {
            throw new InvalidKeyException("Exception extracting key details: " + e.toString());
        }
    }
}
