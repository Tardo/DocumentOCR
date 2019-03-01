package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.util.Arrays;

public class DTLSClientProtocol extends DTLSProtocol {

    protected static class ClientHandshakeState {
        TlsAuthentication authentication = null;
        CertificateRequest certificateRequest = null;
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        TlsCredentials clientCredentials = null;
        Hashtable clientExtensions = null;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        int[] offeredCipherSuites = null;
        short[] offeredCompressionMethods = null;
        boolean secure_renegotiation = false;
        int selectedCipherSuite = -1;
        short selectedCompressionMethod = (short) -1;

        protected ClientHandshakeState() {
        }
    }

    public DTLSClientProtocol(SecureRandom secureRandom) {
        super(secureRandom);
    }

    protected static byte[] parseHelloVerifyRequest(TlsContext tlsContext, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        if (TlsUtils.readVersion(byteArrayInputStream).equals(tlsContext.getServerVersion())) {
            byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return readOpaque8;
        }
        throw new TlsFatalAlert((short) 47);
    }

    protected static byte[] patchClientHelloWithCookie(byte[] bArr, byte[] bArr2) throws IOException {
        int readUint8 = TlsUtils.readUint8(bArr, 34) + 35;
        int i = readUint8 + 1;
        Object obj = new byte[(bArr.length + bArr2.length)];
        System.arraycopy(bArr, 0, obj, 0, readUint8);
        TlsUtils.writeUint8((short) bArr2.length, obj, readUint8);
        System.arraycopy(bArr2, 0, obj, i, bArr2.length);
        System.arraycopy(bArr, i, obj, bArr2.length + i, bArr.length - i);
        return obj;
    }

    protected DTLSTransport clientHandshake(ClientHandshakeState clientHandshakeState, DTLSRecordLayer dTLSRecordLayer) throws IOException {
        SecurityParameters securityParameters = clientHandshakeState.clientContext.getSecurityParameters();
        DTLSReliableHandshake dTLSReliableHandshake = new DTLSReliableHandshake(clientHandshakeState.clientContext, dTLSRecordLayer);
        byte[] generateClientHello = generateClientHello(clientHandshakeState, clientHandshakeState.client);
        dTLSReliableHandshake.sendMessage((short) 1, generateClientHello);
        Message receiveMessage = dTLSReliableHandshake.receiveMessage();
        ProtocolVersion discoveredPeerVersion = dTLSRecordLayer.getDiscoveredPeerVersion();
        if (discoveredPeerVersion.isEqualOrEarlierVersionOf(clientHandshakeState.clientContext.getClientVersion())) {
            byte[] patchClientHelloWithCookie;
            clientHandshakeState.clientContext.setServerVersion(discoveredPeerVersion);
            clientHandshakeState.client.notifyServerVersion(discoveredPeerVersion);
            while (receiveMessage.getType() == (short) 3) {
                patchClientHelloWithCookie = patchClientHelloWithCookie(generateClientHello, parseHelloVerifyRequest(clientHandshakeState.clientContext, receiveMessage.getBody()));
                dTLSReliableHandshake.resetHandshakeMessagesDigest();
                dTLSReliableHandshake.sendMessage((short) 1, patchClientHelloWithCookie);
                receiveMessage = dTLSReliableHandshake.receiveMessage();
            }
            if (receiveMessage.getType() == (short) 2) {
                processServerHello(clientHandshakeState, receiveMessage.getBody());
                receiveMessage = dTLSReliableHandshake.receiveMessage();
                securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(clientHandshakeState.selectedCipherSuite);
                securityParameters.compressionAlgorithm = clientHandshakeState.selectedCompressionMethod;
                securityParameters.verifyDataLength = 12;
                dTLSReliableHandshake.notifyHelloComplete();
                if (receiveMessage.getType() == (short) 23) {
                    processServerSupplementalData(clientHandshakeState, receiveMessage.getBody());
                    receiveMessage = dTLSReliableHandshake.receiveMessage();
                } else {
                    clientHandshakeState.client.processServerSupplementalData(null);
                }
                clientHandshakeState.keyExchange = clientHandshakeState.client.getKeyExchange();
                clientHandshakeState.keyExchange.init(clientHandshakeState.clientContext);
                if (receiveMessage.getType() == (short) 11) {
                    processServerCertificate(clientHandshakeState, receiveMessage.getBody());
                    receiveMessage = dTLSReliableHandshake.receiveMessage();
                } else {
                    clientHandshakeState.keyExchange.skipServerCredentials();
                }
                if (receiveMessage.getType() == (short) 12) {
                    processServerKeyExchange(clientHandshakeState, receiveMessage.getBody());
                    receiveMessage = dTLSReliableHandshake.receiveMessage();
                } else {
                    clientHandshakeState.keyExchange.skipServerKeyExchange();
                }
                if (receiveMessage.getType() == (short) 13) {
                    processCertificateRequest(clientHandshakeState, receiveMessage.getBody());
                    receiveMessage = dTLSReliableHandshake.receiveMessage();
                }
                if (receiveMessage.getType() != (short) 14) {
                    throw new TlsFatalAlert((short) 10);
                } else if (receiveMessage.getBody().length != 0) {
                    throw new TlsFatalAlert((short) 50);
                } else {
                    Vector clientSupplementalData = clientHandshakeState.client.getClientSupplementalData();
                    if (clientSupplementalData != null) {
                        dTLSReliableHandshake.sendMessage((short) 23, DTLSProtocol.generateSupplementalData(clientSupplementalData));
                    }
                    if (clientHandshakeState.certificateRequest != null) {
                        clientHandshakeState.clientCredentials = clientHandshakeState.authentication.getClientCredentials(clientHandshakeState.certificateRequest);
                        Certificate certificate = null;
                        if (clientHandshakeState.clientCredentials != null) {
                            certificate = clientHandshakeState.clientCredentials.getCertificate();
                        }
                        if (certificate == null) {
                            certificate = Certificate.EMPTY_CHAIN;
                        }
                        dTLSReliableHandshake.sendMessage((short) 11, DTLSProtocol.generateCertificate(certificate));
                    }
                    if (clientHandshakeState.clientCredentials != null) {
                        clientHandshakeState.keyExchange.processClientCredentials(clientHandshakeState.clientCredentials);
                    } else {
                        clientHandshakeState.keyExchange.skipClientCredentials();
                    }
                    dTLSReliableHandshake.sendMessage((short) 16, generateClientKeyExchange(clientHandshakeState));
                    TlsProtocol.establishMasterSecret(clientHandshakeState.clientContext, clientHandshakeState.keyExchange);
                    if (clientHandshakeState.clientCredentials instanceof TlsSignerCredentials) {
                        dTLSReliableHandshake.sendMessage((short) 15, generateCertificateVerify(clientHandshakeState, ((TlsSignerCredentials) clientHandshakeState.clientCredentials).generateCertificateSignature(dTLSReliableHandshake.getCurrentHash())));
                    }
                    dTLSRecordLayer.initPendingEpoch(clientHandshakeState.client.getCipher());
                    dTLSReliableHandshake.sendMessage((short) 20, TlsUtils.calculateVerifyData(clientHandshakeState.clientContext, ExporterLabel.client_finished, dTLSReliableHandshake.getCurrentHash()));
                    if (clientHandshakeState.expectSessionTicket) {
                        receiveMessage = dTLSReliableHandshake.receiveMessage();
                        if (receiveMessage.getType() == (short) 4) {
                            processNewSessionTicket(clientHandshakeState, receiveMessage.getBody());
                        } else {
                            throw new TlsFatalAlert((short) 10);
                        }
                    }
                    patchClientHelloWithCookie = TlsUtils.calculateVerifyData(clientHandshakeState.clientContext, ExporterLabel.server_finished, dTLSReliableHandshake.getCurrentHash());
                    Message receiveMessage2 = dTLSReliableHandshake.receiveMessage();
                    if (receiveMessage2.getType() == (short) 20) {
                        processFinished(receiveMessage2.getBody(), patchClientHelloWithCookie);
                        dTLSReliableHandshake.finish();
                        clientHandshakeState.client.notifyHandshakeComplete();
                        return new DTLSTransport(dTLSRecordLayer);
                    }
                    throw new TlsFatalAlert((short) 10);
                }
            }
            throw new TlsFatalAlert((short) 10);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public DTLSTransport connect(TlsClient tlsClient, DatagramTransport datagramTransport) throws IOException {
        if (tlsClient == null) {
            throw new IllegalArgumentException("'client' cannot be null");
        } else if (datagramTransport == null) {
            throw new IllegalArgumentException("'transport' cannot be null");
        } else {
            SecurityParameters securityParameters = new SecurityParameters();
            securityParameters.entity = 1;
            securityParameters.clientRandom = TlsProtocol.createRandomBlock(this.secureRandom);
            ClientHandshakeState clientHandshakeState = new ClientHandshakeState();
            clientHandshakeState.client = tlsClient;
            clientHandshakeState.clientContext = new TlsClientContextImpl(this.secureRandom, securityParameters);
            tlsClient.init(clientHandshakeState.clientContext);
            DTLSRecordLayer dTLSRecordLayer = new DTLSRecordLayer(datagramTransport, clientHandshakeState.clientContext, tlsClient, (short) 22);
            try {
                return clientHandshake(clientHandshakeState, dTLSRecordLayer);
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

    protected byte[] generateCertificateVerify(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeOpaque16(bArr, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected byte[] generateClientHello(ClientHandshakeState clientHandshakeState, TlsClient tlsClient) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ProtocolVersion clientVersion = tlsClient.getClientVersion();
        if (clientVersion.isDTLS()) {
            clientHandshakeState.clientContext.setClientVersion(clientVersion);
            TlsUtils.writeVersion(clientVersion, byteArrayOutputStream);
            byteArrayOutputStream.write(clientHandshakeState.clientContext.getSecurityParameters().getClientRandom());
            TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, byteArrayOutputStream);
            TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, byteArrayOutputStream);
            clientHandshakeState.offeredCipherSuites = tlsClient.getCipherSuites();
            clientHandshakeState.clientExtensions = tlsClient.getClientExtensions();
            short s = (clientHandshakeState.clientExtensions == null || clientHandshakeState.clientExtensions.get(TlsProtocol.EXT_RenegotiationInfo) == null) ? (short) 1 : (short) 0;
            int length = clientHandshakeState.offeredCipherSuites.length;
            if (s != (short) 0) {
                length++;
            }
            TlsUtils.writeUint16(length * 2, byteArrayOutputStream);
            TlsUtils.writeUint16Array(clientHandshakeState.offeredCipherSuites, byteArrayOutputStream);
            if (s != (short) 0) {
                TlsUtils.writeUint16(255, byteArrayOutputStream);
            }
            clientHandshakeState.offeredCompressionMethods = new short[]{(short) 0};
            TlsUtils.writeUint8((short) clientHandshakeState.offeredCompressionMethods.length, byteArrayOutputStream);
            TlsUtils.writeUint8Array(clientHandshakeState.offeredCompressionMethods, byteArrayOutputStream);
            if (clientHandshakeState.clientExtensions != null) {
                TlsProtocol.writeExtensions(byteArrayOutputStream, clientHandshakeState.clientExtensions);
            }
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    protected byte[] generateClientKeyExchange(ClientHandshakeState clientHandshakeState) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        clientHandshakeState.keyExchange.generateClientKeyExchange(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected void processCertificateRequest(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        if (clientHandshakeState.authentication == null) {
            throw new TlsFatalAlert((short) 40);
        }
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        clientHandshakeState.certificateRequest = CertificateRequest.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        clientHandshakeState.keyExchange.validateCertificateRequest(clientHandshakeState.certificateRequest);
    }

    protected void processNewSessionTicket(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        NewSessionTicket parse = NewSessionTicket.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        clientHandshakeState.client.notifyNewSessionTicket(parse);
    }

    protected void processServerCertificate(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        Certificate parse = Certificate.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        clientHandshakeState.keyExchange.processServerCertificate(parse);
        clientHandshakeState.authentication = clientHandshakeState.client.getAuthentication();
        clientHandshakeState.authentication.notifyServerCertificate(parse);
    }

    protected void processServerHello(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        SecurityParameters securityParameters = clientHandshakeState.clientContext.getSecurityParameters();
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        if (TlsUtils.readVersion(byteArrayInputStream).equals(clientHandshakeState.clientContext.getServerVersion())) {
            securityParameters.serverRandom = TlsUtils.readFully(32, byteArrayInputStream);
            byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream);
            if (readOpaque8.length > 32) {
                throw new TlsFatalAlert((short) 47);
            }
            clientHandshakeState.client.notifySessionID(readOpaque8);
            clientHandshakeState.selectedCipherSuite = TlsUtils.readUint16(byteArrayInputStream);
            if (!TlsProtocol.arrayContains(clientHandshakeState.offeredCipherSuites, clientHandshakeState.selectedCipherSuite) || clientHandshakeState.selectedCipherSuite == 0 || clientHandshakeState.selectedCipherSuite == 255) {
                throw new TlsFatalAlert((short) 47);
            }
            DTLSProtocol.validateSelectedCipherSuite(clientHandshakeState.selectedCipherSuite, (short) 47);
            clientHandshakeState.client.notifySelectedCipherSuite(clientHandshakeState.selectedCipherSuite);
            clientHandshakeState.selectedCompressionMethod = TlsUtils.readUint8(byteArrayInputStream);
            if (TlsProtocol.arrayContains(clientHandshakeState.offeredCompressionMethods, clientHandshakeState.selectedCompressionMethod)) {
                clientHandshakeState.client.notifySelectedCompressionMethod(clientHandshakeState.selectedCompressionMethod);
                Hashtable readExtensions = TlsProtocol.readExtensions(byteArrayInputStream);
                if (readExtensions != null) {
                    Enumeration keys = readExtensions.keys();
                    while (keys.hasMoreElements()) {
                        Integer num = (Integer) keys.nextElement();
                        if (!num.equals(TlsProtocol.EXT_RenegotiationInfo) && (clientHandshakeState.clientExtensions == null || clientHandshakeState.clientExtensions.get(num) == null)) {
                            throw new TlsFatalAlert((short) 110);
                        }
                    }
                    readOpaque8 = (byte[]) readExtensions.get(TlsProtocol.EXT_RenegotiationInfo);
                    if (readOpaque8 != null) {
                        clientHandshakeState.secure_renegotiation = true;
                        if (!Arrays.constantTimeAreEqual(readOpaque8, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                            throw new TlsFatalAlert((short) 40);
                        }
                    }
                    clientHandshakeState.expectSessionTicket = readExtensions.containsKey(TlsProtocol.EXT_SessionTicket);
                }
                clientHandshakeState.client.notifySecureRenegotiation(clientHandshakeState.secure_renegotiation);
                if (clientHandshakeState.clientExtensions != null) {
                    clientHandshakeState.client.processServerExtensions(readExtensions);
                    return;
                }
                return;
            }
            throw new TlsFatalAlert((short) 47);
        }
        throw new TlsFatalAlert((short) 47);
    }

    protected void processServerKeyExchange(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        clientHandshakeState.keyExchange.processServerKeyExchange(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
    }

    protected void processServerSupplementalData(ClientHandshakeState clientHandshakeState, byte[] bArr) throws IOException {
        clientHandshakeState.client.processServerSupplementalData(TlsProtocol.readSupplementalDataMessage(new ByteArrayInputStream(bArr)));
    }
}
