package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public abstract class AbstractTlsServer extends AbstractTlsPeer implements TlsServer {
    protected TlsCipherFactory cipherFactory;
    protected short[] clientECPointFormats;
    protected Hashtable clientExtensions;
    protected ProtocolVersion clientVersion;
    protected TlsServerContext context;
    protected boolean eccCipherSuitesOffered;
    protected int[] namedCurves;
    protected int[] offeredCipherSuites;
    protected short[] offeredCompressionMethods;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected short[] serverECPointFormats;
    protected Hashtable serverExtensions;
    protected ProtocolVersion serverVersion;
    protected Vector supportedSignatureAlgorithms;

    public AbstractTlsServer() {
        this(new DefaultTlsCipherFactory());
    }

    public AbstractTlsServer(TlsCipherFactory tlsCipherFactory) {
        this.cipherFactory = tlsCipherFactory;
    }

    public CertificateRequest getCertificateRequest() {
        return null;
    }

    protected abstract int[] getCipherSuites();

    public TlsCompression getCompression() throws IOException {
        switch (this.selectedCompressionMethod) {
            case (short) 0:
                return new TlsNullCompression();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    protected short[] getCompressionMethods() {
        return new short[]{(short) 0};
    }

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.TLSv11;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv10;
    }

    public NewSessionTicket getNewSessionTicket() throws IOException {
        return new NewSessionTicket(0, TlsUtils.EMPTY_BYTES);
    }

    public int getSelectedCipherSuite() throws IOException {
        boolean supportsClientECCCapabilities = supportsClientECCCapabilities(this.namedCurves, this.clientECPointFormats);
        int[] cipherSuites = getCipherSuites();
        int i = 0;
        while (i < cipherSuites.length) {
            int i2 = cipherSuites[i];
            if (!TlsProtocol.arrayContains(this.offeredCipherSuites, i2) || (!supportsClientECCCapabilities && TlsECCUtils.isECCCipherSuite(i2))) {
                i++;
            } else {
                this.selectedCipherSuite = i2;
                return i2;
            }
        }
        throw new TlsFatalAlert((short) 40);
    }

    public short getSelectedCompressionMethod() throws IOException {
        short[] compressionMethods = getCompressionMethods();
        for (int i = 0; i < compressionMethods.length; i++) {
            if (TlsProtocol.arrayContains(this.offeredCompressionMethods, compressionMethods[i])) {
                short s = compressionMethods[i];
                this.selectedCompressionMethod = s;
                return s;
            }
        }
        throw new TlsFatalAlert((short) 40);
    }

    public Hashtable getServerExtensions() throws IOException {
        if (this.clientECPointFormats == null || !TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite)) {
            return null;
        }
        this.serverECPointFormats = new short[]{(short) 2, (short) 1, (short) 0};
        this.serverExtensions = new Hashtable();
        TlsECCUtils.addSupportedPointFormatsExtension(this.serverExtensions, this.serverECPointFormats);
        return this.serverExtensions;
    }

    public Vector getServerSupplementalData() throws IOException {
        return null;
    }

    public ProtocolVersion getServerVersion() throws IOException {
        if (getMinimumVersion().isEqualOrEarlierVersionOf(this.clientVersion)) {
            ProtocolVersion maximumVersion = getMaximumVersion();
            if (this.clientVersion.isEqualOrEarlierVersionOf(maximumVersion)) {
                maximumVersion = this.clientVersion;
                this.serverVersion = maximumVersion;
                return maximumVersion;
            } else if (this.clientVersion.isLaterVersionOf(maximumVersion)) {
                this.serverVersion = maximumVersion;
                return maximumVersion;
            }
        }
        throw new TlsFatalAlert((short) 70);
    }

    public void init(TlsServerContext tlsServerContext) {
        this.context = tlsServerContext;
    }

    public void notifyClientCertificate(Certificate certificate) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    public void notifyClientVersion(ProtocolVersion protocolVersion) throws IOException {
        this.clientVersion = protocolVersion;
    }

    public void notifyHandshakeComplete() throws IOException {
    }

    public void notifyOfferedCipherSuites(int[] iArr) throws IOException {
        this.offeredCipherSuites = iArr;
        this.eccCipherSuitesOffered = TlsECCUtils.containsECCCipherSuites(this.offeredCipherSuites);
    }

    public void notifyOfferedCompressionMethods(short[] sArr) throws IOException {
        this.offeredCompressionMethods = sArr;
    }

    public void notifySecureRenegotiation(boolean z) throws IOException {
        if (!z) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    public void processClientExtensions(Hashtable hashtable) throws IOException {
        this.clientExtensions = hashtable;
        if (hashtable != null) {
            this.supportedSignatureAlgorithms = TlsUtils.getSignatureAlgorithmsExtension(hashtable);
            if (this.supportedSignatureAlgorithms == null || TlsUtils.isSignatureAlgorithmsExtensionAllowed(this.clientVersion)) {
                this.namedCurves = TlsECCUtils.getSupportedEllipticCurvesExtension(hashtable);
                this.clientECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(hashtable);
            } else {
                throw new TlsFatalAlert((short) 47);
            }
        }
        if (!this.eccCipherSuitesOffered) {
            if (this.namedCurves != null || this.clientECPointFormats != null) {
                throw new TlsFatalAlert((short) 47);
            }
        }
    }

    public void processClientSupplementalData(Vector vector) throws IOException {
        if (vector != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    protected boolean supportsClientECCCapabilities(int[] iArr, short[] sArr) {
        if (iArr == null) {
            return TlsECCUtils.hasAnySupportedNamedCurves();
        }
        for (int i : iArr) {
            if (!NamedCurve.refersToASpecificNamedCurve(i) || TlsECCUtils.isSupportedNamedCurve(i)) {
                return true;
            }
        }
        return false;
    }
}
