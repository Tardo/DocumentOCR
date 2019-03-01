package org.bouncycastle.openssl.jcajce;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;

public class JcaPEMKeyConverter {
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public KeyPair getKeyPair(PEMKeyPair pEMKeyPair) throws PEMException {
        try {
            String id = pEMKeyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();
            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(id)) {
                id = "ECDSA";
            }
            KeyFactory createKeyFactory = this.helper.createKeyFactory(id);
            return new KeyPair(createKeyFactory.generatePublic(new X509EncodedKeySpec(pEMKeyPair.getPublicKeyInfo().getEncoded())), createKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pEMKeyPair.getPrivateKeyInfo().getEncoded())));
        } catch (Exception e) {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws PEMException {
        try {
            String id = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(id)) {
                id = "ECDSA";
            }
            return this.helper.createKeyFactory(id).generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
        } catch (Exception e) {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PublicKey getPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws PEMException {
        try {
            String id = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(id)) {
                id = "ECDSA";
            }
            return this.helper.createKeyFactory(id).generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded()));
        } catch (Exception e) {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public JcaPEMKeyConverter setProvider(String str) {
        this.helper = new NamedJcaJceHelper(str);
        return this;
    }

    public JcaPEMKeyConverter setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }
}
