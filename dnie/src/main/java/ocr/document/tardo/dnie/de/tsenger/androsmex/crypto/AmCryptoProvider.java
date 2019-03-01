package de.tsenger.androsmex.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Security;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public abstract class AmCryptoProvider {
    byte[] buf = new byte[16];
    protected PaddedBufferedBlockCipher decryptCipher = null;
    protected PaddedBufferedBlockCipher encryptCipher = null;
    byte[] obuf = new byte[512];

    public abstract byte[] decryptBlock(byte[] bArr, byte[] bArr2);

    public abstract int getBlockSize();

    public abstract byte[] getMAC(byte[] bArr);

    public abstract byte[] getMAC(byte[] bArr, byte[] bArr2);

    public abstract void init(byte[] bArr, byte[] bArr2);

    public AmCryptoProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] encrypt(byte[] in) throws AmCryptoException {
        ByteArrayInputStream bin = new ByteArrayInputStream(in);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        while (true) {
            try {
                int noBytesRead = bin.read(this.buf);
                if (noBytesRead >= 0) {
                    bout.write(this.obuf, 0, this.encryptCipher.processBytes(this.buf, 0, noBytesRead, this.obuf, 0));
                } else {
                    try {
                        bout.write(this.obuf, 0, this.encryptCipher.doFinal(this.obuf, 0));
                        bout.flush();
                        bin.close();
                        bout.close();
                        return bout.toByteArray();
                    } catch (Throwable e) {
                        throw new AmCryptoException(e);
                    } catch (Throwable e2) {
                        throw new AmCryptoException(e2);
                    } catch (Throwable e22) {
                        throw new AmCryptoException(e22);
                    } catch (Throwable e222) {
                        throw new AmCryptoException(e222);
                    }
                }
            } catch (Throwable e2222) {
                throw new AmCryptoException(e2222);
            } catch (Throwable e22222) {
                throw new AmCryptoException(e22222);
            } catch (Throwable e222222) {
                throw new AmCryptoException(e222222);
            }
        }
    }

    public byte[] decrypt(byte[] in) throws AmCryptoException {
        ByteArrayInputStream bin = new ByteArrayInputStream(in);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        while (true) {
            try {
                int noBytesRead = bin.read(this.buf);
                if (noBytesRead >= 0) {
                    bout.write(this.obuf, 0, this.decryptCipher.processBytes(this.buf, 0, noBytesRead, this.obuf, 0));
                } else {
                    try {
                        bout.write(this.obuf, 0, this.decryptCipher.doFinal(this.obuf, 0));
                        bout.flush();
                        bin.close();
                        bout.close();
                        return bout.toByteArray();
                    } catch (Throwable e) {
                        throw new AmCryptoException(e);
                    } catch (Throwable e2) {
                        throw new AmCryptoException(e2);
                    } catch (Throwable e22) {
                        throw new AmCryptoException(e22);
                    } catch (Throwable e222) {
                        throw new AmCryptoException(e222);
                    }
                }
            } catch (Throwable e2222) {
                throw new AmCryptoException(e2222);
            } catch (Throwable e22222) {
                throw new AmCryptoException(e22222);
            } catch (Throwable e222222) {
                throw new AmCryptoException(e222222);
            }
        }
    }

    public byte[] addPadding(byte[] data) {
        int len = data.length;
        byte[] n = new byte[(((len / getBlockSize()) + 1) * getBlockSize())];
        System.arraycopy(data, 0, n, 0, data.length);
        new ISO7816d4Padding().addPadding(n, len);
        return n;
    }

    public byte[] removePadding(byte[] b) {
        int i = b.length - 1;
        do {
            i--;
        } while (b[i] == (byte) 0);
        if (b[i] != Byte.MIN_VALUE) {
            return b;
        }
        byte[] rd = new byte[i];
        System.arraycopy(b, 0, rd, 0, rd.length);
        return rd;
    }
}
