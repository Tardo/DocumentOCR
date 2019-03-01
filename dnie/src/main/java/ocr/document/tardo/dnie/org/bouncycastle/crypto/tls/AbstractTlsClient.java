package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsClient extends AbstractTlsPeer implements TlsClient {
    protected TlsCipherFactory cipherFactory;
    protected TlsClientContext context;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected Vector supportedSignatureAlgorithms;

    public AbstractTlsClient() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsClient(TlsCipherFactory tlsCipherFactory) {
        this.cipherFactory = tlsCipherFactory;
    }

    public Hashtable getClientExtensions() throws IOException {
        if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(this.context.getClientVersion())) {
            return null;
        }
        short[] sArr = new short[]{(short) 6, (short) 5, (short) 4, (short) 3, (short) 2};
        short[] sArr2 = new short[]{(short) 1};
        this.supportedSignatureAlgorithms = new Vector();
        for (short signatureAndHashAlgorithm : sArr) {
            for (short signatureAndHashAlgorithm2 : sArr2) {
                this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(signatureAndHashAlgorithm, signatureAndHashAlgorithm2));
            }
        }
        this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm((short) 2, (short) 2));
        Hashtable hashtable = null == null ? new Hashtable() : null;
        TlsUtils.addSignatureAlgorithmsExtension(hashtable, this.supportedSignatureAlgorithms);
        return hashtable;
    }

    public ProtocolVersion getClientHelloRecordLayerVersion() {
        return getClientVersion();
    }

    public Vector getClientSupplementalData() throws IOException {
        return null;
    }

    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.TLSv11;
    }

    public TlsCompression getCompression() throws IOException {
        switch (this.selectedCompressionMethod) {
            case (short) 0:
                return new TlsNullCompression();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    public short[] getCompressionMethods() {
        return new short[]{(short) 0};
    }

    public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv10;
    }

    public void init(TlsClientContext tlsClientContext) {
        this.context = tlsClientContext;
    }

    public void notifyHandshakeComplete() throws IOException {
    }

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket) throws IOException {
    }

    public void notifySecureRenegotiation(boolean z) throws IOException {
        if (!z) {
        }
    }

    public void notifySelectedCipherSuite(int i) {
        this.selectedCipherSuite = i;
    }

    public void notifySelectedCompressionMethod(short s) {
        this.selectedCompressionMethod = s;
    }

    public void notifyServerVersion(ProtocolVersion protocolVersion) throws IOException {
        if (!getMinimumVersion().isEqualOrEarlierVersionOf(protocolVersion)) {
            throw new TlsFatalAlert((short) 70);
        }
    }

    public void notifySessionID(byte[] bArr) {
    }

    public void processServerExtensions(Hashtable hashtable) throws IOException {
        if (hashtable != null && hashtable.containsKey(TlsUtils.EXT_signature_algorithms)) {
            throw new TlsFatalAlert((short) 47);
        }
    }

    public void processServerSupplementalData(Vector vector) throws IOException {
        if (vector != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }
}
