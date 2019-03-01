package org.bouncycastle.crypto.tls;

import java.io.IOException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class TlsStreamCipher implements TlsCipher {
    protected TlsContext context;
    protected StreamCipher decryptCipher;
    protected StreamCipher encryptCipher;
    protected TlsMac readMac;
    protected TlsMac writeMac;

    public TlsStreamCipher(TlsContext tlsContext, StreamCipher streamCipher, StreamCipher streamCipher2, Digest digest, Digest digest2, int i) throws IOException {
        boolean isServer = tlsContext.isServer();
        this.context = tlsContext;
        this.encryptCipher = streamCipher;
        this.decryptCipher = streamCipher2;
        int digestSize = ((i * 2) + digest.getDigestSize()) + digest2.getDigestSize();
        byte[] calculateKeyBlock = TlsUtils.calculateKeyBlock(tlsContext, digestSize);
        TlsMac tlsMac = new TlsMac(tlsContext, digest, calculateKeyBlock, 0, digest.getDigestSize());
        int digestSize2 = 0 + digest.getDigestSize();
        TlsMac tlsMac2 = new TlsMac(tlsContext, digest2, calculateKeyBlock, digestSize2, digest2.getDigestSize());
        int digestSize3 = digestSize2 + digest2.getDigestSize();
        KeyParameter keyParameter = new KeyParameter(calculateKeyBlock, digestSize3, i);
        int i2 = digestSize3 + i;
        CipherParameters keyParameter2 = new KeyParameter(calculateKeyBlock, i2, i);
        if (i2 + i != digestSize) {
            throw new TlsFatalAlert((short) 80);
        }
        CipherParameters cipherParameters;
        if (isServer) {
            this.writeMac = tlsMac2;
            this.readMac = tlsMac;
            this.encryptCipher = streamCipher2;
            this.decryptCipher = streamCipher;
            cipherParameters = keyParameter;
        } else {
            this.writeMac = tlsMac;
            this.readMac = tlsMac2;
            this.encryptCipher = streamCipher;
            this.decryptCipher = streamCipher2;
            cipherParameters = keyParameter2;
            Object obj = keyParameter;
        }
        this.encryptCipher.init(true, keyParameter2);
        this.decryptCipher.init(false, cipherParameters);
    }

    public byte[] decodeCiphertext(long j, short s, byte[] bArr, int i, int i2) throws IOException {
        int size = this.readMac.getSize();
        if (i2 < size) {
            throw new TlsFatalAlert((short) 50);
        }
        byte[] bArr2 = new byte[i2];
        this.decryptCipher.processBytes(bArr, i, i2, bArr2, 0);
        size = i2 - size;
        if (Arrays.constantTimeAreEqual(Arrays.copyOfRange(bArr2, size, i2), this.readMac.calculateMac(j, s, bArr2, 0, size))) {
            return Arrays.copyOfRange(bArr2, 0, size);
        }
        throw new TlsFatalAlert((short) 20);
    }

    public byte[] encodePlaintext(long j, short s, byte[] bArr, int i, int i2) {
        byte[] calculateMac = this.writeMac.calculateMac(j, s, bArr, i, i2);
        byte[] bArr2 = new byte[(calculateMac.length + i2)];
        this.encryptCipher.processBytes(bArr, i, i2, bArr2, 0);
        this.encryptCipher.processBytes(calculateMac, 0, calculateMac.length, bArr2, i2);
        return bArr2;
    }

    public int getPlaintextLimit(int i) {
        return i - this.writeMac.getSize();
    }
}
