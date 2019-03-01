package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public interface TlsServer extends TlsPeer {
    CertificateRequest getCertificateRequest();

    TlsCipher getCipher() throws IOException;

    TlsCompression getCompression() throws IOException;

    TlsCredentials getCredentials() throws IOException;

    TlsKeyExchange getKeyExchange() throws IOException;

    NewSessionTicket getNewSessionTicket() throws IOException;

    int getSelectedCipherSuite() throws IOException;

    short getSelectedCompressionMethod() throws IOException;

    Hashtable getServerExtensions() throws IOException;

    Vector getServerSupplementalData() throws IOException;

    ProtocolVersion getServerVersion() throws IOException;

    void init(TlsServerContext tlsServerContext);

    void notifyClientCertificate(Certificate certificate) throws IOException;

    void notifyClientVersion(ProtocolVersion protocolVersion) throws IOException;

    void notifyHandshakeComplete() throws IOException;

    void notifyOfferedCipherSuites(int[] iArr) throws IOException;

    void notifyOfferedCompressionMethods(short[] sArr) throws IOException;

    void notifySecureRenegotiation(boolean z) throws IOException;

    void processClientExtensions(Hashtable hashtable) throws IOException;

    void processClientSupplementalData(Vector vector) throws IOException;
}
