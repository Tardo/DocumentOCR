package org.bouncycastle.crypto.encodings;

import custom.org.apache.harmony.security.fortress.PolicyUtils;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class PKCS1Encoding implements AsymmetricBlockCipher {
    private static final int HEADER_LENGTH = 10;
    public static final String STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.strict";
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private SecureRandom random;
    private boolean useStrictLength = useStrict();

    /* renamed from: org.bouncycastle.crypto.encodings.PKCS1Encoding$1 */
    class C00901 implements PrivilegedAction {
        C00901() {
        }

        public Object run() {
            return System.getProperty(PKCS1Encoding.STRICT_LENGTH_ENABLED_PROPERTY);
        }
    }

    public PKCS1Encoding(AsymmetricBlockCipher asymmetricBlockCipher) {
        this.engine = asymmetricBlockCipher;
    }

    private byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        Object processBlock = this.engine.processBlock(bArr, i, i2);
        if (processBlock.length < getOutputBlockSize()) {
            throw new InvalidCipherTextException("block truncated");
        }
        byte b = processBlock[0];
        if (this.forPrivateKey) {
            if (b != (byte) 2) {
                throw new InvalidCipherTextException("unknown block type");
            }
        } else if (b != (byte) 1) {
            throw new InvalidCipherTextException("unknown block type");
        }
        if (!this.useStrictLength || processBlock.length == this.engine.getOutputBlockSize()) {
            int i3 = 1;
            while (i3 != processBlock.length) {
                byte b2 = processBlock[i3];
                if (b2 == (byte) 0) {
                    break;
                } else if (b != (byte) 1 || b2 == (byte) -1) {
                    i3++;
                } else {
                    throw new InvalidCipherTextException("block padding incorrect");
                }
            }
            i3++;
            if (i3 > processBlock.length || i3 < 10) {
                throw new InvalidCipherTextException("no data in block");
            }
            Object obj = new byte[(processBlock.length - i3)];
            System.arraycopy(processBlock, i3, obj, 0, obj.length);
            return obj;
        }
        throw new InvalidCipherTextException("block incorrect size");
    }

    private byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        int i3 = 1;
        if (i2 > getInputBlockSize()) {
            throw new IllegalArgumentException("input data too large");
        }
        Object obj = new byte[this.engine.getInputBlockSize()];
        if (this.forPrivateKey) {
            obj[0] = 1;
            while (i3 != (obj.length - i2) - 1) {
                obj[i3] = (byte) -1;
                i3++;
            }
        } else {
            this.random.nextBytes(obj);
            obj[0] = (byte) 2;
            while (i3 != (obj.length - i2) - 1) {
                while (obj[i3] == (byte) 0) {
                    obj[i3] = (byte) this.random.nextInt();
                }
                i3++;
            }
        }
        obj[(obj.length - i2) - 1] = null;
        System.arraycopy(bArr, i, obj, obj.length - i2, i2);
        return this.engine.processBlock(obj, 0, obj.length);
    }

    private boolean useStrict() {
        String str = (String) AccessController.doPrivileged(new C00901());
        return str == null || str.equals(PolicyUtils.TRUE);
    }

    public int getInputBlockSize() {
        int inputBlockSize = this.engine.getInputBlockSize();
        return this.forEncryption ? inputBlockSize - 10 : inputBlockSize;
    }

    public int getOutputBlockSize() {
        int outputBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? outputBlockSize : outputBlockSize - 10;
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        AsymmetricKeyParameter asymmetricKeyParameter;
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            asymmetricKeyParameter = (AsymmetricKeyParameter) parametersWithRandom.getParameters();
        } else {
            this.random = new SecureRandom();
            asymmetricKeyParameter = (AsymmetricKeyParameter) cipherParameters;
        }
        this.engine.init(z, cipherParameters);
        this.forPrivateKey = asymmetricKeyParameter.isPrivate();
        this.forEncryption = z;
    }

    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }
}
