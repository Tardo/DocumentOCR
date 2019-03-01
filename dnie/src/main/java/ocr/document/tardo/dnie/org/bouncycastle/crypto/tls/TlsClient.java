package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public interface TlsClient extends TlsPeer {
    TlsAuthentication getAuthentication() throws IOException;

    TlsCipher getCipher() throws IOException;

    int[] getCipherSuites();

    Hashtable getClientExtensions() throws IOException;

    ProtocolVersion getClientHelloRecordLayerVersion();

    Vector getClientSupplementalData() throws IOException;

    ProtocolVersion getClientVersion();

    TlsCompression getCompression() throws IOException;

    short[] getCompressionMethods();

    TlsKeyExchange getKeyExchange() throws IOException;

    void init(TlsClientContext tlsClientContext);

    void notifyHandshakeComplete() throws IOException;

    void notifyNewSessionTicket(NewSessionTicket newSessionTicket) throws IOException;

    void notifySecureRenegotiation(boolean z) throws IOException;

    void notifySelectedCipherSuite(int i);

    void notifySelectedCompressionMethod(short s);

    void notifyServerVersion(ProtocolVersion protocolVersion) throws IOException;

    void notifySessionID(byte[] bArr);

    void processServerExtensions(Hashtable hashtable) throws IOException;

    void processServerSupplementalData(Vector vector) throws IOException;
}
