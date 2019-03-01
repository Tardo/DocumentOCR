package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class DTLSServerProtocol extends DTLSProtocol {
    protected boolean verifyRequests = true;

    protected static class ServerHandshakeState {
        CertificateRequest certificateRequest = null;
        Certificate clientCertificate = null;
        short clientCertificateType = (short) -1;
        Hashtable clientExtensions;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        int[] offeredCipherSuites;
        short[] offeredCompressionMethods;
        boolean secure_renegotiation = false;
        int selectedCipherSuite = -1;
        short selectedCompressionMethod = (short) -1;
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        TlsCredentials serverCredentials = null;
        Hashtable serverExtensions = null;

        protected ServerHandshakeState() {
        }
    }

    public DTLSServerProtocol(SecureRandom secureRandom) {
        super(secureRandom);
    }

    public DTLSTransport accept(TlsServer tlsServer, DatagramTransport datagramTransport) throws IOException {
        if (tlsServer == null) {
            throw new IllegalArgumentException("'server' cannot be null");
        } else if (datagramTransport == null) {
            throw new IllegalArgumentException("'transport' cannot be null");
        } else {
            SecurityParameters securityParameters = new SecurityParameters();
            securityParameters.entity = 0;
            securityParameters.serverRandom = TlsProtocol.createRandomBlock(this.secureRandom);
            ServerHandshakeState serverHandshakeState = new ServerHandshakeState();
            serverHandshakeState.server = tlsServer;
            serverHandshakeState.serverContext = new TlsServerContextImpl(this.secureRandom, securityParameters);
            tlsServer.init(serverHandshakeState.serverContext);
            DTLSRecordLayer dTLSRecordLayer = new DTLSRecordLayer(datagramTransport, serverHandshakeState.serverContext, tlsServer, (short) 22);
            try {
                return serverHandshake(serverHandshakeState, dTLSRecordLayer);
            } catch (TlsFatalAlert e) {
                dTLSRecordLayer.fail(e.getAlertDescription());
                throw e;
            } catch (IOException e2) {
                dTLSRecordLayer.fail((short) 80);
                throw e2;
            } catch (RuntimeException e3) {
                dTLSRecordLayer.fail((short) 80);
                throw new TlsFatalAlert((short) 80);
            }
        }
    }

    protected boolean expectCertificateVerifyMessage(ServerHandshakeState serverHandshakeState) {
        return serverHandshakeState.clientCertificateType >= (short) 0 && TlsUtils.hasSigningCapability(serverHandshakeState.clientCertificateType);
    }

    protected byte[] generateCertificateRequest(ServerHandshakeState serverHandshakeState, CertificateRequest certificateRequest) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificateRequest.encode(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateNewSessionTicket(ServerHandshakeState serverHandshakeState, NewSessionTicket newSessionTicket) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        newSessionTicket.encode(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateServerHello(ServerHandshakeState serverHandshakeState) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ProtocolVersion serverVersion = serverHandshakeState.server.getServerVersion();
        if (serverVersion.isEqualOrEarlierVersionOf(serverHandshakeState.serverContext.getClientVersion())) {
            serverHandshakeState.serverContext.setServerVersion(serverVersion);
            TlsUtils.writeVersion(serverHandshakeState.serverContext.getServerVersion(), byteArrayOutputStream);
            byteArrayOutputStream.write(serverHandshakeState.serverContext.getSecurityParameters().serverRandom);
            TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, byteArrayOutputStream);
            serverHandshakeState.selectedCipherSuite = serverHandshakeState.server.getSelectedCipherSuite();
            if (!TlsProtocol.arrayContains(serverHandshakeState.offeredCipherSuites, serverHandshakeState.selectedCipherSuite) || serverHandshakeState.selectedCipherSuite == 0 || serverHandshakeState.selectedCipherSuite == 255) {
                throw new TlsFatalAlert((short) 80);
            }
            DTLSProtocol.validateSelectedCipherSuite(serverHandshakeState.selectedCipherSuite, (short) 80);
            serverHandshakeState.selectedCompressionMethod = serverHandshakeState.server.getSelectedCompressionMethod();
            if (TlsProtocol.arrayContains(serverHandshakeState.offeredCompressionMethods, serverHandshakeState.selectedCompressionMethod)) {
                TlsUtils.writeUint16(serverHandshakeState.selectedCipherSuite, byteArrayOutputStream);
                TlsUtils.writeUint8(serverHandshakeState.selectedCompressionMethod, byteArrayOutputStream);
                serverHandshakeState.serverExtensions = serverHandshakeState.server.getServerExtensions();
                if (serverHandshakeState.secure_renegotiation) {
                    Object obj = (serverHandshakeState.serverExtensions == null || !serverHandshakeState.serverExtensions.containsKey(TlsProtocol.EXT_RenegotiationInfo)) ? 1 : null;
                    if (obj != null) {
                        if (serverHandshakeState.serverExtensions == null) {
                            serverHandshakeState.serverExtensions = new Hashtable();
                        }
                        serverHandshakeState.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                    }
                }
                if (serverHandshakeState.serverExtensions != null) {
                    serverHandshakeState.expectSessionTicket = serverHandshakeState.serverExtensions.containsKey(TlsProtocol.EXT_SessionTicket);
                    TlsProtocol.writeExtensions(byteArrayOutputStream, serverHandshakeState.serverExtensions);
                }
                return byteArrayOutputStream.toByteArray();
            }
            throw new TlsFatalAlert((short) 80);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public boolean getVerifyRequests() {
        return this.verifyRequests;
    }

    protected void notifyClientCertificate(ServerHandshakeState serverHandshakeState, Certificate certificate) throws IOException {
        if (serverHandshakeState.certificateRequest == null) {
            throw new IllegalStateException();
        } else if (serverHandshakeState.clientCertificate != null) {
            throw new TlsFatalAlert((short) 10);
        } else {
            serverHandshakeState.clientCertificate = certificate;
            if (certificate.isEmpty()) {
                serverHandshakeState.keyExchange.skipClientCredentials();
            } else {
                serverHandshakeState.clientCertificateType = TlsUtils.getClientCertificateType(certificate, serverHandshakeState.serverCredentials.getCertificate());
                serverHandshakeState.keyExchange.processClientCertificate(certificate);
            }
            serverHandshakeState.server.notifyClientCertificate(certificate);
        }
    }

    protected void processCertificateVerify(ServerHandshakeState serverHandshakeState, byte[] bArr, byte[] bArr2) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        try {
            TlsSigner createTlsSigner = TlsUtils.createTlsSigner(serverHandshakeState.clientCertificateType);
            createTlsSigner.init(serverHandshakeState.serverContext);
            createTlsSigner.verifyRawSignature(readOpaque16, PublicKeyFactory.createKey(serverHandshakeState.clientCertificate.getCertificateAt(0).getSubjectPublicKeyInfo()), bArr2);
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 51);
        }
    }

    protected void processClientCertificate(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        Certificate parse = Certificate.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        notifyClientCertificate(serverHandshakeState, parse);
    }

    protected void processClientHello(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        ProtocolVersion readVersion = TlsUtils.readVersion(byteArrayInputStream);
        if (readVersion.isDTLS()) {
            byte[] readFully = TlsUtils.readFully(32, byteArrayInputStream);
            if (TlsUtils.readOpaque8(byteArrayInputStream).length > 32) {
                throw new TlsFatalAlert((short) 47);
            }
            TlsUtils.readOpaque8(byteArrayInputStream);
            int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
            if (readUint16 < 2 || (readUint16 & 1) != 0) {
                throw new TlsFatalAlert((short) 50);
            }
            serverHandshakeState.offeredCipherSuites = TlsUtils.readUint16Array(readUint16 / 2, byteArrayInputStream);
            short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
            if (readUint8 < (short) 1) {
                throw new TlsFatalAlert((short) 47);
            }
            serverHandshakeState.offeredCompressionMethods = TlsUtils.readUint8Array(readUint8, byteArrayInputStream);
            serverHandshakeState.clientExtensions = TlsProtocol.readExtensions(byteArrayInputStream);
            serverHandshakeState.serverContext.setClientVersion(readVersion);
            serverHandshakeState.server.notifyClientVersion(readVersion);
            serverHandshakeState.serverContext.getSecurityParameters().clientRandom = readFully;
            serverHandshakeState.server.notifyOfferedCipherSuites(serverHandshakeState.offeredCipherSuites);
            serverHandshakeState.server.notifyOfferedCompressionMethods(serverHandshakeState.offeredCompressionMethods);
            if (TlsProtocol.arrayContains(serverHandshakeState.offeredCipherSuites, 255)) {
                serverHandshakeState.secure_renegotiation = true;
            }
            if (serverHandshakeState.clientExtensions != null) {
                byte[] bArr2 = (byte[]) serverHandshakeState.clientExtensions.get(TlsProtocol.EXT_RenegotiationInfo);
                if (bArr2 != null) {
                    serverHandshakeState.secure_renegotiation = true;
                    if (!Arrays.constantTimeAreEqual(bArr2, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                        throw new TlsFatalAlert((short) 40);
                    }
                }
            }
            serverHandshakeState.server.notifySecureRenegotiation(serverHandshakeState.secure_renegotiation);
            if (serverHandshakeState.clientExtensions != null) {
                serverHandshakeState.server.processClientExtensions(serverHandshakeState.clientExtensions);
                return;
            }
            return;
        }
        throw new TlsFatalAlert((short) 47);
    }

    protected void processClientKeyExchange(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        serverHandshakeState.keyExchange.processClientKeyExchange(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        TlsProtocol.establishMasterSecret(serverHandshakeState.serverContext, serverHandshakeState.keyExchange);
    }

    protected void processClientSupplementalData(ServerHandshakeState serverHandshakeState, byte[] bArr) throws IOException {
        serverHandshakeState.server.processClientSupplementalData(TlsProtocol.readSupplementalDataMessage(new ByteArrayInputStream(bArr)));
    }

    public DTLSTransport serverHandshake(ServerHandshakeState serverHandshakeState, DTLSRecordLayer dTLSRecordLayer) throws IOException {
        SecurityParameters securityParameters = serverHandshakeState.serverContext.getSecurityParameters();
        DTLSReliableHandshake dTLSReliableHandshake = new DTLSReliableHandshake(serverHandshakeState.serverContext, dTLSRecordLayer);
        Message receiveMessage = dTLSReliableHandshake.receiveMessage();
        serverHandshakeState.serverContext.setClientVersion(dTLSRecordLayer.getDiscoveredPeerVersion());
        if (receiveMessage.getType() == (short) 1) {
            processClientHello(serverHandshakeState, receiveMessage.getBody());
            dTLSReliableHandshake.sendMessage((short) 2, generateServerHello(serverHandshakeState));
            securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(serverHandshakeState.selectedCipherSuite);
            securityParameters.compressionAlgorithm = serverHandshakeState.selectedCompressionMethod;
            securityParameters.verifyDataLength = 12;
            dTLSReliableHandshake.notifyHelloComplete();
            Vector serverSupplementalData = serverHandshakeState.server.getServerSupplementalData();
            if (serverSupplementalData != null) {
                dTLSReliableHandshake.sendMessage((short) 23, DTLSProtocol.generateSupplementalData(serverSupplementalData));
            }
            serverHandshakeState.keyExchange = serverHandshakeState.server.getKeyExchange();
            serverHandshakeState.keyExchange.init(serverHandshakeState.serverContext);
            serverHandshakeState.serverCredentials = serverHandshakeState.server.getCredentials();
            if (serverHandshakeState.serverCredentials == null) {
                serverHandshakeState.keyExchange.skipServerCredentials();
            } else {
                serverHandshakeState.keyExchange.processServerCredentials(serverHandshakeState.serverCredentials);
                dTLSReliableHandshake.sendMessage((short) 11, DTLSProtocol.generateCertificate(serverHandshakeState.serverCredentials.getCertificate()));
            }
            byte[] generateServerKeyExchange = serverHandshakeState.keyExchange.generateServerKeyExchange();
            if (generateServerKeyExchange != null) {
                dTLSReliableHandshake.sendMessage((short) 12, generateServerKeyExchange);
            }
            if (serverHandshakeState.serverCredentials != null) {
                serverHandshakeState.certificateRequest = serverHandshakeState.server.getCertificateRequest();
                if (serverHandshakeState.certificateRequest != null) {
                    serverHandshakeState.keyExchange.validateCertificateRequest(serverHandshakeState.certificateRequest);
                    dTLSReliableHandshake.sendMessage((short) 13, generateCertificateRequest(serverHandshakeState, serverHandshakeState.certificateRequest));
                }
            }
            dTLSReliableHandshake.sendMessage((short) 14, TlsUtils.EMPTY_BYTES);
            Message receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            if (receiveMessage2.getType() == (short) 23) {
                processClientSupplementalData(serverHandshakeState, receiveMessage2.getBody());
                receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            } else {
                serverHandshakeState.server.processClientSupplementalData(null);
            }
            if (serverHandshakeState.certificateRequest == null) {
                serverHandshakeState.keyExchange.skipClientCredentials();
            } else if (receiveMessage2.getType() == (short) 11) {
                processClientCertificate(serverHandshakeState, receiveMessage2.getBody());
                receiveMessage2 = dTLSReliableHandshake.receiveMessage();
            } else {
                if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverHandshakeState.serverContext.getServerVersion().getEquivalentTLSVersion())) {
                    throw new TlsFatalAlert((short) 10);
                }
                notifyClientCertificate(serverHandshakeState, Certificate.EMPTY_CHAIN);
            }
            if (receiveMessage2.getType() == (short) 16) {
                processClientKeyExchange(serverHandshakeState, receiveMessage2.getBody());
                dTLSRecordLayer.initPendingEpoch(serverHandshakeState.server.getCipher());
                if (expectCertificateVerifyMessage(serverHandshakeState)) {
                    generateServerKeyExchange = dTLSReliableHandshake.getCurrentHash();
                    receiveMessage = dTLSReliableHandshake.receiveMessage();
                    if (receiveMessage.getType() == (short) 15) {
                        processCertificateVerify(serverHandshakeState, receiveMessage.getBody(), generateServerKeyExchange);
                    } else {
                        throw new TlsFatalAlert((short) 10);
                    }
                }
                generateServerKeyExchange = dTLSReliableHandshake.getCurrentHash();
                receiveMessage = dTLSReliableHandshake.receiveMessage();
                if (receiveMessage.getType() == (short) 20) {
                    processFinished(receiveMessage.getBody(), TlsUtils.calculateVerifyData(serverHandshakeState.serverContext, ExporterLabel.client_finished, generateServerKeyExchange));
                    if (serverHandshakeState.expectSessionTicket) {
                        dTLSReliableHandshake.sendMessage((short) 4, generateNewSessionTicket(serverHandshakeState, serverHandshakeState.server.getNewSessionTicket()));
                    }
                    dTLSReliableHandshake.sendMessage((short) 20, TlsUtils.calculateVerifyData(serverHandshakeState.serverContext, ExporterLabel.server_finished, dTLSReliableHandshake.getCurrentHash()));
                    dTLSReliableHandshake.finish();
                    serverHandshakeState.server.notifyHandshakeComplete();
                    return new DTLSTransport(dTLSRecordLayer);
                }
                throw new TlsFatalAlert((short) 10);
            }
            throw new TlsFatalAlert((short) 10);
        }
        throw new TlsFatalAlert((short) 10);
    }

    public void setVerifyRequests(boolean z) {
        this.verifyRequests = z;
    }
}
