package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.LongDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class TlsMac {
    protected TlsContext context;
    protected int digestBlockSize;
    protected int digestOverhead;
    protected Mac mac;
    protected byte[] secret;

    public TlsMac(TlsContext tlsContext, Digest digest, byte[] bArr, int i, int i2) {
        this.context = tlsContext;
        CipherParameters keyParameter = new KeyParameter(bArr, i, i2);
        this.secret = Arrays.clone(keyParameter.getKey());
        if (digest instanceof LongDigest) {
            this.digestBlockSize = 128;
            this.digestOverhead = 16;
        } else {
            this.digestBlockSize = 64;
            this.digestOverhead = 8;
        }
        if (tlsContext.getServerVersion().isSSL()) {
            this.mac = new SSL3Mac(digest);
            if (digest.getDigestSize() == 20) {
                this.digestOverhead = 4;
            }
        } else {
            this.mac = new HMac(digest);
        }
        this.mac.init(keyParameter);
    }

    private int getDigestBlockCount(int i) {
        return (this.digestOverhead + i) / this.digestBlockSize;
    }

    public byte[] calculateMac(long j, short s, byte[] bArr, int i, int i2) {
        ProtocolVersion serverVersion = this.context.getServerVersion();
        boolean isSSL = serverVersion.isSSL();
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream(isSSL ? 11 : 13);
        try {
            TlsUtils.writeUint64(j, byteArrayOutputStream);
            TlsUtils.writeUint8(s, byteArrayOutputStream);
            if (!isSSL) {
                TlsUtils.writeVersion(serverVersion, byteArrayOutputStream);
            }
            TlsUtils.writeUint16(i2, byteArrayOutputStream);
            byte[] toByteArray = byteArrayOutputStream.toByteArray();
            this.mac.update(toByteArray, 0, toByteArray.length);
            this.mac.update(bArr, i, i2);
            toByteArray = new byte[this.mac.getMacSize()];
            this.mac.doFinal(toByteArray, 0);
            return toByteArray;
        } catch (IOException e) {
            throw new IllegalStateException("Internal error during mac calculation");
        }
    }

    public byte[] calculateMacConstantTime(long j, short s, byte[] bArr, int i, int i2, int i3, byte[] bArr2) {
        byte[] calculateMac = calculateMac(j, s, bArr, i, i2);
        int i4 = this.context.getServerVersion().isSSL() ? 11 : 13;
        i4 = getDigestBlockCount(i4 + i3) - getDigestBlockCount(i4 + i2);
        while (true) {
            i4--;
            if (i4 >= 0) {
                this.mac.update(bArr2, 0, this.digestBlockSize);
            } else {
                this.mac.update(bArr2[0]);
                this.mac.reset();
                return calculateMac;
            }
        }
    }

    public byte[] getMACSecret() {
        return this.secret;
    }

    public int getSize() {
        return this.mac.getMacSize();
    }
}
