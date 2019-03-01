package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLException;

public class DigitalSignature {
    private final Cipher cipher;
    private final MessageDigest md5;
    private byte[] md5_hash;
    private final MessageDigest sha;
    private byte[] sha_hash;
    private final Signature signature;

    public DigitalSignature(int keyExchange) {
        try {
            this.sha = MessageDigest.getInstance("SHA-1");
            if (keyExchange == CipherSuite.KeyExchange_RSA_EXPORT || keyExchange == CipherSuite.KeyExchange_RSA || keyExchange == CipherSuite.KeyExchange_DHE_RSA || keyExchange == CipherSuite.KeyExchange_DHE_RSA_EXPORT) {
                this.md5 = MessageDigest.getInstance("MD5");
                this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                this.signature = null;
            } else if (keyExchange == CipherSuite.KeyExchange_DHE_DSS || keyExchange == CipherSuite.KeyExchange_DHE_DSS_EXPORT) {
                this.signature = Signature.getInstance("NONEwithDSA");
                this.cipher = null;
                this.md5 = null;
            } else {
                this.cipher = null;
                this.signature = null;
                this.md5 = null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (NoSuchPaddingException e2) {
            throw new AssertionError(e2);
        }
    }

    public void init(PrivateKey key) {
        try {
            if (this.signature != null) {
                this.signature.initSign(key);
            } else if (this.cipher != null) {
                this.cipher.init(1, key);
            }
        } catch (InvalidKeyException e) {
            throw new AlertException((byte) 42, new SSLException("init - invalid private key", e));
        }
    }

    public void init(Certificate cert) {
        try {
            if (this.signature != null) {
                this.signature.initVerify(cert);
            } else if (this.cipher != null) {
                this.cipher.init(2, cert);
            }
        } catch (InvalidKeyException e) {
            throw new AlertException((byte) 42, new SSLException("init - invalid certificate", e));
        }
    }

    public void update(byte[] data) {
        if (this.sha != null) {
            this.sha.update(data);
        }
        if (this.md5 != null) {
            this.md5.update(data);
        }
    }

    public void setMD5(byte[] data) {
        this.md5_hash = data;
    }

    public void setSHA(byte[] data) {
        this.sha_hash = data;
    }

    public byte[] sign() {
        try {
            if (this.md5 != null && this.md5_hash == null) {
                this.md5_hash = new byte[16];
                this.md5.digest(this.md5_hash, 0, this.md5_hash.length);
            }
            if (this.md5_hash != null) {
                if (this.signature != null) {
                    this.signature.update(this.md5_hash);
                } else if (this.cipher != null) {
                    this.cipher.update(this.md5_hash);
                }
            }
            if (this.sha != null && this.sha_hash == null) {
                this.sha_hash = new byte[20];
                this.sha.digest(this.sha_hash, 0, this.sha_hash.length);
            }
            if (this.sha_hash != null) {
                if (this.signature != null) {
                    this.signature.update(this.sha_hash);
                } else if (this.cipher != null) {
                    this.cipher.update(this.sha_hash);
                }
            }
            if (this.signature != null) {
                return this.signature.sign();
            }
            if (this.cipher != null) {
                return this.cipher.doFinal();
            }
            return new byte[0];
        } catch (DigestException e) {
            return new byte[0];
        } catch (SignatureException e2) {
            return new byte[0];
        } catch (BadPaddingException e3) {
            return new byte[0];
        } catch (IllegalBlockSizeException e4) {
            return new byte[0];
        }
    }

    public boolean verifySignature(byte[] data) {
        boolean z = false;
        if (this.signature != null) {
            try {
                return this.signature.verify(data);
            } catch (SignatureException e) {
                return z;
            }
        } else if (this.cipher != null) {
            try {
                byte[] md5_sha;
                byte[] decrypt = this.cipher.doFinal(data);
                if (this.md5_hash != null && this.sha_hash != null) {
                    md5_sha = new byte[(this.md5_hash.length + this.sha_hash.length)];
                    System.arraycopy(this.md5_hash, z, md5_sha, z, this.md5_hash.length);
                    System.arraycopy(this.sha_hash, z, md5_sha, this.md5_hash.length, this.sha_hash.length);
                } else if (this.md5_hash != null) {
                    md5_sha = this.md5_hash;
                } else {
                    md5_sha = this.sha_hash;
                }
                return Arrays.equals(decrypt, md5_sha);
            } catch (IllegalBlockSizeException e2) {
                return z;
            } catch (BadPaddingException e3) {
                return z;
            }
        } else if (data == null || data.length == 0) {
            return true;
        } else {
            return z;
        }
    }
}
