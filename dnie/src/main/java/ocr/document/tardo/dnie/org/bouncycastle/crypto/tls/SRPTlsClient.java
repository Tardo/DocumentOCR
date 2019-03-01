package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public abstract class SRPTlsClient extends AbstractTlsClient {
    public static final Integer EXT_SRP = Integers.valueOf(12);
    protected byte[] identity;
    protected byte[] password;

    public SRPTlsClient(TlsCipherFactory tlsCipherFactory, byte[] bArr, byte[] bArr2) {
        super(tlsCipherFactory);
        this.identity = Arrays.clone(bArr);
        this.password = Arrays.clone(bArr2);
    }

    public SRPTlsClient(byte[] bArr, byte[] bArr2) {
        this.identity = Arrays.clone(bArr);
        this.password = Arrays.clone(bArr2);
    }

    protected TlsKeyExchange createSRPKeyExchange(int i) {
        return new TlsSRPKeyExchange(i, this.supportedSignatureAlgorithms, this.identity, this.password);
    }

    public TlsCipher getCipher() throws IOException {
        switch (this.selectedCipherSuite) {
            case 49178:
            case 49179:
            case 49180:
                return this.cipherFactory.createCipher(this.context, 7, 2);
            case 49181:
            case 49182:
            case 49183:
                return this.cipherFactory.createCipher(this.context, 8, 2);
            case 49184:
            case 49185:
            case 49186:
                return this.cipherFactory.createCipher(this.context, 9, 2);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public int[] getCipherSuites() {
        return new int[]{49185, 49182, 49179, 49184, 49181, 49178};
    }

    public Hashtable getClientExtensions() throws IOException {
        Hashtable clientExtensions = super.getClientExtensions();
        if (clientExtensions == null) {
            clientExtensions = new Hashtable();
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeOpaque8(this.identity, byteArrayOutputStream);
        clientExtensions.put(EXT_SRP, byteArrayOutputStream.toByteArray());
        return clientExtensions;
    }

    public TlsKeyExchange getKeyExchange() throws IOException {
        switch (this.selectedCipherSuite) {
            case 49178:
            case 49181:
            case 49184:
                return createSRPKeyExchange(21);
            case 49179:
            case 49182:
            case 49185:
                return createSRPKeyExchange(23);
            case 49180:
            case 49183:
            case 49186:
                return createSRPKeyExchange(22);
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public void processServerExtensions(Hashtable hashtable) throws IOException {
        if (hashtable != null) {
            byte[] bArr = (byte[]) hashtable.get(EXT_SRP);
            if (bArr != null && bArr.length > 0) {
                throw new TlsFatalAlert((short) 47);
            }
        }
    }
}
