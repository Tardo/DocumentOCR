package custom.org.apache.harmony.security.provider.crypto;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public final class CryptoProvider extends Provider {
    private static final long serialVersionUID = 7991202868423459598L;

    /* renamed from: custom.org.apache.harmony.security.provider.crypto.CryptoProvider$1 */
    class C00521 implements PrivilegedAction<Void> {
        C00521() {
        }

        public Void run() {
            CryptoProvider.this.put("MessageDigest.SHA-1", "org.apache.harmony.security.provider.crypto.SHA1_MessageDigestImpl");
            CryptoProvider.this.put("MessageDigest.SHA-1 ImplementedIn", "Software");
            CryptoProvider.this.put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
            CryptoProvider.this.put("Alg.Alias.MessageDigest.SHA", "SHA-1");
            CryptoProvider.this.put("Signature.SHA1withDSA", "org.apache.harmony.security.provider.crypto.SHA1withDSA_SignatureImpl");
            CryptoProvider.this.put("Signature.SHA1withDSA ImplementedIn", "Software");
            CryptoProvider.this.put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.DSAwithSHA1", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.DSA", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.DSS", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.OID.1.2.840.10040.4.3", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.1.2.840.10040.4.3", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.1.3.14.3.2.13", "SHA1withDSA");
            CryptoProvider.this.put("Alg.Alias.Signature.1.3.14.3.2.27", "SHA1withDSA");
            CryptoProvider.this.put("KeyFactory.DSA", "org.apache.harmony.security.provider.crypto.DSAKeyFactoryImpl");
            CryptoProvider.this.put("KeyFactory.DSA ImplementedIn", "Software");
            CryptoProvider.this.put("Alg.Alias.KeyFactory.1.3.14.3.2.12", "DSA");
            CryptoProvider.this.put("Alg.Alias.KeyFactory.1.2.840.10040.4.1", "DSA");
            return null;
        }
    }

    public CryptoProvider() {
        super("Crypto", 1.0d, "HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)");
        String MD_NAME = "org.apache.harmony.security.provider.crypto.SHA1_MessageDigestImpl";
        String SR_NAME = "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl";
        String SIGN_NAME = "org.apache.harmony.security.provider.crypto.SHA1withDSA_SignatureImpl";
        String SIGN_ALIAS = "SHA1withDSA";
        String KEYF_NAME = "org.apache.harmony.security.provider.crypto.DSAKeyFactoryImpl";
        AccessController.doPrivileged(new C00521());
    }
}
