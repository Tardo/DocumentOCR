package org.bouncycastle.mozilla;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SignedPublicKeyAndChallenge extends ASN1Object {
    private PublicKeyAndChallenge pkac = PublicKeyAndChallenge.getInstance(this.spkacSeq.getObjectAt(0));
    private DERBitString signature = ((DERBitString) this.spkacSeq.getObjectAt(2));
    private AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.getInstance(this.spkacSeq.getObjectAt(1));
    private ASN1Sequence spkacSeq;

    public SignedPublicKeyAndChallenge(byte[] bArr) {
        this.spkacSeq = toDERSequence(bArr);
    }

    private static ASN1Sequence toDERSequence(byte[] bArr) {
        try {
            return (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(bArr)).readObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("badly encoded request");
        }
    }

    public PublicKey getPublicKey(String str) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        ASN1Encodable subjectPublicKeyInfo = this.pkac.getSubjectPublicKeyInfo();
        try {
            return KeyFactory.getInstance(subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId(), str).generatePublic(new X509EncodedKeySpec(new DERBitString(subjectPublicKeyInfo).getBytes()));
        } catch (Exception e) {
            throw new InvalidKeyException("error encoding public key");
        }
    }

    public PublicKeyAndChallenge getPublicKeyAndChallenge() {
        return this.pkac;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.spkacSeq;
    }

    public boolean verify() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        return verify(null);
    }

    public boolean verify(String str) throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        Signature instance = str == null ? Signature.getInstance(this.signatureAlgorithm.getAlgorithm().getId()) : Signature.getInstance(this.signatureAlgorithm.getAlgorithm().getId(), str);
        instance.initVerify(getPublicKey(str));
        try {
            instance.update(new DERBitString(this.pkac).getBytes());
            return instance.verify(this.signature.getBytes());
        } catch (Exception e) {
            throw new InvalidKeyException("error encoding public key");
        }
    }
}
