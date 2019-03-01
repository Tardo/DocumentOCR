package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.crypto.Digest;

class RecordStream {
    private static int CIPHERTEXT_LIMIT = (COMPRESSED_LIMIT + 1024);
    private static int COMPRESSED_LIMIT = (PLAINTEXT_LIMIT + 1024);
    private static int PLAINTEXT_LIMIT = 16384;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private TlsContext context = null;
    private TlsProtocol handler;
    private TlsHandshakeHash hash = null;
    private InputStream input;
    private OutputStream output;
    private TlsCipher pendingCipher = null;
    private TlsCompression pendingCompression = null;
    private TlsCipher readCipher = null;
    private TlsCompression readCompression = null;
    private long readSeqNo = 0;
    private ProtocolVersion readVersion = null;
    private boolean restrictReadVersion = true;
    private TlsCipher writeCipher = null;
    private TlsCompression writeCompression = null;
    private long writeSeqNo = 0;
    private ProtocolVersion writeVersion = null;

    RecordStream(TlsProtocol tlsProtocol, InputStream inputStream, OutputStream outputStream) {
        this.handler = tlsProtocol;
        this.input = inputStream;
        this.output = outputStream;
        this.readCompression = new TlsNullCompression();
        this.writeCompression = this.readCompression;
        this.readCipher = new TlsNullCipher(this.context);
        this.writeCipher = this.readCipher;
    }

    private static void checkLength(int i, int i2, short s) throws IOException {
        if (i > i2) {
            throw new TlsFatalAlert(s);
        }
    }

    private static void checkType(short s, short s2) throws IOException {
        switch (s) {
            case (short) 20:
            case (short) 21:
            case (short) 22:
            case (short) 23:
                return;
            default:
                throw new TlsFatalAlert(s2);
        }
    }

    private static byte[] doFinal(Digest digest) {
        byte[] bArr = new byte[digest.getDigestSize()];
        digest.doFinal(bArr, 0);
        return bArr;
    }

    private byte[] getBufferContents() {
        byte[] toByteArray = this.buffer.toByteArray();
        this.buffer.reset();
        return toByteArray;
    }

    protected void close() throws IOException {
        IOException iOException = null;
        try {
            this.input.close();
        } catch (IOException e) {
            iOException = e;
        }
        try {
            this.output.close();
        } catch (IOException e2) {
            iOException = e2;
        }
        if (iOException != null) {
            throw iOException;
        }
    }

    protected byte[] decodeAndVerify(short s, InputStream inputStream, int i) throws IOException {
        checkLength(i, CIPHERTEXT_LIMIT, (short) 22);
        byte[] readFully = TlsUtils.readFully(i, inputStream);
        TlsCipher tlsCipher = this.readCipher;
        long j = this.readSeqNo;
        this.readSeqNo = 1 + j;
        byte[] decodeCiphertext = tlsCipher.decodeCiphertext(j, s, readFully, 0, readFully.length);
        checkLength(decodeCiphertext.length, COMPRESSED_LIMIT, (short) 22);
        OutputStream decompress = this.readCompression.decompress(this.buffer);
        if (decompress != this.buffer) {
            decompress.write(decodeCiphertext, 0, decodeCiphertext.length);
            decompress.flush();
            decodeCiphertext = getBufferContents();
        }
        checkLength(decodeCiphertext.length, PLAINTEXT_LIMIT, (short) 30);
        return decodeCiphertext;
    }

    void finaliseHandshake() throws IOException {
        if (this.readCompression == this.pendingCompression && this.writeCompression == this.pendingCompression && this.readCipher == this.pendingCipher && this.writeCipher == this.pendingCipher) {
            this.pendingCompression = null;
            this.pendingCipher = null;
            return;
        }
        throw new TlsFatalAlert((short) 40);
    }

    protected void flush() throws IOException {
        this.output.flush();
    }

    byte[] getCurrentHash(byte[] bArr) {
        Digest fork = this.hash.fork();
        if (this.context.getServerVersion().isSSL() && bArr != null) {
            fork.update(bArr, 0, bArr.length);
        }
        return doFinal(fork);
    }

    ProtocolVersion getReadVersion() {
        return this.readVersion;
    }

    void init(TlsContext tlsContext) {
        this.context = tlsContext;
        this.hash = new DeferredHash();
        this.hash.init(tlsContext);
    }

    void notifyHelloComplete() {
        this.hash = this.hash.commit();
    }

    public void readRecord() throws IOException {
        short readUint8 = TlsUtils.readUint8(this.input);
        checkType(readUint8, (short) 10);
        if (this.restrictReadVersion) {
            ProtocolVersion readVersion = TlsUtils.readVersion(this.input);
            if (this.readVersion == null) {
                this.readVersion = readVersion;
            } else if (!readVersion.equals(this.readVersion)) {
                throw new TlsFatalAlert((short) 47);
            }
        } else if ((TlsUtils.readVersionRaw(this.input) & -256) != 768) {
            throw new TlsFatalAlert((short) 47);
        }
        byte[] decodeAndVerify = decodeAndVerify(readUint8, this.input, TlsUtils.readUint16(this.input));
        this.handler.processRecord(readUint8, decodeAndVerify, 0, decodeAndVerify.length);
    }

    void receivedReadCipherSpec() throws IOException {
        if (this.pendingCompression == null || this.pendingCipher == null) {
            throw new TlsFatalAlert((short) 40);
        }
        this.readCompression = this.pendingCompression;
        this.readCipher = this.pendingCipher;
        this.readSeqNo = 0;
    }

    void sentWriteCipherSpec() throws IOException {
        if (this.pendingCompression == null || this.pendingCipher == null) {
            throw new TlsFatalAlert((short) 40);
        }
        this.writeCompression = this.pendingCompression;
        this.writeCipher = this.pendingCipher;
        this.writeSeqNo = 0;
    }

    void setPendingConnectionState(TlsCompression tlsCompression, TlsCipher tlsCipher) {
        this.pendingCompression = tlsCompression;
        this.pendingCipher = tlsCipher;
    }

    void setReadVersion(ProtocolVersion protocolVersion) {
        this.readVersion = protocolVersion;
    }

    void setRestrictReadVersion(boolean z) {
        this.restrictReadVersion = z;
    }

    void setWriteVersion(ProtocolVersion protocolVersion) {
        this.writeVersion = protocolVersion;
    }

    void updateHandshakeData(byte[] bArr, int i, int i2) {
        this.hash.update(bArr, i, i2);
    }

    protected void writeRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        checkType(s, (short) 80);
        checkLength(i2, PLAINTEXT_LIMIT, (short) 80);
        if (i2 >= 1 || s == (short) 23) {
            Object encodePlaintext;
            if (s == (short) 22) {
                updateHandshakeData(bArr, i, i2);
            }
            OutputStream compress = this.writeCompression.compress(this.buffer);
            TlsCipher tlsCipher;
            long j;
            if (compress == this.buffer) {
                tlsCipher = this.writeCipher;
                j = this.writeSeqNo;
                this.writeSeqNo = j + 1;
                encodePlaintext = tlsCipher.encodePlaintext(j, s, bArr, i, i2);
            } else {
                compress.write(bArr, i, i2);
                compress.flush();
                byte[] bufferContents = getBufferContents();
                checkLength(bufferContents.length, i2 + 1024, (short) 80);
                tlsCipher = this.writeCipher;
                j = this.writeSeqNo;
                this.writeSeqNo = 1 + j;
                encodePlaintext = tlsCipher.encodePlaintext(j, s, bufferContents, 0, bufferContents.length);
            }
            checkLength(encodePlaintext.length, CIPHERTEXT_LIMIT, (short) 80);
            Object obj = new byte[(encodePlaintext.length + 5)];
            TlsUtils.writeUint8(s, obj, 0);
            TlsUtils.writeVersion(this.writeVersion, obj, 1);
            TlsUtils.writeUint16(encodePlaintext.length, obj, 3);
            System.arraycopy(encodePlaintext, 0, obj, 5, encodePlaintext.length);
            this.output.write(obj);
            this.output.flush();
            return;
        }
        throw new TlsFatalAlert((short) 80);
    }
}
