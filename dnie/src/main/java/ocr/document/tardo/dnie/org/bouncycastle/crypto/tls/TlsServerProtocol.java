package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class TlsServerProtocol extends TlsProtocol {
    protected CertificateRequest certificateRequest = null;
    protected byte[] certificateVerifyHash = null;
    protected Certificate clientCertificate = null;
    protected short clientCertificateType = (short) -1;
    protected Hashtable clientExtensions;
    protected TlsKeyExchange keyExchange = null;
    protected int[] offeredCipherSuites;
    protected short[] offeredCompressionMethods;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected TlsCredentials serverCredentials = null;
    protected Hashtable serverExtensions;
    protected TlsServer tlsServer = null;
    protected TlsServerContextImpl tlsServerContext = null;

    public TlsServerProtocol(InputStream inputStream, OutputStream outputStream, SecureRandom secureRandom) {
        super(inputStream, outputStream, secureRandom);
    }

    public void accept(TlsServer tlsServer) throws IOException {
        if (tlsServer == null) {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        } else if (this.tlsServer != null) {
            throw new IllegalStateException("accept can only be called once");
        } else {
            this.tlsServer = tlsServer;
            this.securityParameters = new SecurityParameters();
            this.securityParameters.entity = 0;
            this.securityParameters.serverRandom = TlsProtocol.createRandomBlock(this.secureRandom);
            this.tlsServerContext = new TlsServerContextImpl(this.secureRandom, this.securityParameters);
            this.tlsServer.init(this.tlsServerContext);
            this.recordStream.init(this.tlsServerContext);
            this.recordStream.setRestrictReadVersion(false);
            completeHandshake();
            this.tlsServer.notifyHandshakeComplete();
        }
    }

    protected boolean expectCertificateVerifyMessage() {
        return this.clientCertificateType >= (short) 0 && TlsUtils.hasSigningCapability(this.clientCertificateType);
    }

    protected AbstractTlsContext getContext() {
        return this.tlsServerContext;
    }

    protected TlsPeer getPeer() {
        return this.tlsServer;
    }

    protected void handleChangeCipherSpecMessage() throws IOException {
        switch (this.connection_state) {
            case (short) 10:
                if (this.certificateVerifyHash != null) {
                    failWithError((short) 2, (short) 10);
                    break;
                }
                break;
            case (short) 11:
                break;
            default:
                failWithError((short) 2, (short) 40);
                return;
        }
        this.connection_state = (short) 12;
    }

    protected void handleHandshakeMessage(short s, byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        switch (s) {
            case (short) 1:
                switch (this.connection_state) {
                    case (short) 0:
                        receiveClientHelloMessage(byteArrayInputStream);
                        this.connection_state = (short) 1;
                        sendServerHelloMessage();
                        this.connection_state = (short) 2;
                        this.securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(this.selectedCipherSuite);
                        this.securityParameters.compressionAlgorithm = this.selectedCompressionMethod;
                        this.securityParameters.verifyDataLength = 12;
                        this.recordStream.notifyHelloComplete();
                        Vector serverSupplementalData = this.tlsServer.getServerSupplementalData();
                        if (serverSupplementalData != null) {
                            sendSupplementalDataMessage(serverSupplementalData);
                        }
                        this.connection_state = (short) 3;
                        this.keyExchange = this.tlsServer.getKeyExchange();
                        this.keyExchange.init(getContext());
                        this.serverCredentials = this.tlsServer.getCredentials();
                        if (this.serverCredentials == null) {
                            this.keyExchange.skipServerCredentials();
                        } else {
                            this.keyExchange.processServerCredentials(this.serverCredentials);
                            sendCertificateMessage(this.serverCredentials.getCertificate());
                        }
                        this.connection_state = (short) 4;
                        byte[] generateServerKeyExchange = this.keyExchange.generateServerKeyExchange();
                        if (generateServerKeyExchange != null) {
                            sendServerKeyExchangeMessage(generateServerKeyExchange);
                        }
                        this.connection_state = (short) 5;
                        if (this.serverCredentials != null) {
                            this.certificateRequest = this.tlsServer.getCertificateRequest();
                            if (this.certificateRequest != null) {
                                this.keyExchange.validateCertificateRequest(this.certificateRequest);
                                sendCertificateRequestMessage(this.certificateRequest);
                            }
                        }
                        this.connection_state = (short) 6;
                        sendServerHelloDoneMessage();
                        this.connection_state = (short) 7;
                        return;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
            case (short) 11:
                switch (this.connection_state) {
                    case (short) 7:
                        this.tlsServer.processClientSupplementalData(null);
                        break;
                    case (short) 8:
                        break;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
                if (this.certificateRequest == null) {
                    failWithError((short) 2, (short) 10);
                }
                receiveCertificateMessage(byteArrayInputStream);
                this.connection_state = (short) 9;
                return;
            case (short) 15:
                switch (this.connection_state) {
                    case (short) 10:
                        if (this.certificateVerifyHash == null) {
                            failWithError((short) 2, (short) 10);
                        }
                        receiveCertificateVerifyMessage(byteArrayInputStream);
                        this.connection_state = (short) 11;
                        return;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
            case (short) 16:
                switch (this.connection_state) {
                    case (short) 7:
                        this.tlsServer.processClientSupplementalData(null);
                        break;
                    case (short) 8:
                        break;
                    case (short) 9:
                        break;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
                if (this.certificateRequest == null) {
                    this.keyExchange.skipClientCredentials();
                } else {
                    ProtocolVersion equivalentTLSVersion = getContext().getServerVersion().getEquivalentTLSVersion();
                    if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(equivalentTLSVersion)) {
                        failWithError((short) 2, (short) 10);
                    } else if (!equivalentTLSVersion.isSSL()) {
                        notifyClientCertificate(Certificate.EMPTY_CHAIN);
                    } else if (this.clientCertificate == null) {
                        failWithError((short) 2, (short) 10);
                    }
                }
                receiveClientKeyExchangeMessage(byteArrayInputStream);
                this.connection_state = (short) 10;
                return;
            case (short) 20:
                switch (this.connection_state) {
                    case (short) 12:
                        processFinishedMessage(byteArrayInputStream);
                        this.connection_state = (short) 13;
                        if (this.expectSessionTicket) {
                            sendNewSessionTicketMessage(this.tlsServer.getNewSessionTicket());
                        }
                        this.connection_state = (short) 14;
                        sendChangeCipherSpecMessage();
                        this.connection_state = (short) 15;
                        sendFinishedMessage();
                        this.connection_state = (short) 16;
                        return;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
            case (short) 23:
                switch (this.connection_state) {
                    case (short) 7:
                        this.tlsServer.processClientSupplementalData(TlsProtocol.readSupplementalDataMessage(byteArrayInputStream));
                        this.connection_state = (short) 8;
                        return;
                    default:
                        failWithError((short) 2, (short) 10);
                        return;
                }
            default:
                failWithError((short) 2, (short) 10);
                return;
        }
    }

    protected void handleWarningMessage(short s) throws IOException {
        switch (s) {
            case EACTags.INTERCHANGE_PROFILE /*41*/:
                if (getContext().getServerVersion().isSSL() && this.certificateRequest != null) {
                    notifyClientCertificate(Certificate.EMPTY_CHAIN);
                    return;
                }
                return;
            default:
                super.handleWarningMessage(s);
                return;
        }
    }

    protected void notifyClientCertificate(Certificate certificate) throws IOException {
        if (this.certificateRequest == null) {
            throw new IllegalStateException();
        } else if (this.clientCertificate != null) {
            throw new TlsFatalAlert((short) 10);
        } else {
            this.clientCertificate = certificate;
            if (certificate.isEmpty()) {
                this.keyExchange.skipClientCredentials();
            } else {
                this.clientCertificateType = TlsUtils.getClientCertificateType(certificate, this.serverCredentials.getCertificate());
                this.keyExchange.processClientCertificate(certificate);
            }
            this.tlsServer.notifyClientCertificate(certificate);
        }
    }

    protected void receiveCertificateMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        Certificate parse = Certificate.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        notifyClientCertificate(parse);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        try {
            TlsSigner createTlsSigner = TlsUtils.createTlsSigner(this.clientCertificateType);
            createTlsSigner.init(getContext());
            createTlsSigner.verifyRawSignature(readOpaque16, PublicKeyFactory.createKey(this.clientCertificate.getCertificateAt(0).getSubjectPublicKeyInfo()), this.certificateVerifyHash);
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 51);
        }
    }

    protected void receiveClientHelloMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        ProtocolVersion readVersion = TlsUtils.readVersion(byteArrayInputStream);
        if (readVersion.isDTLS()) {
            failWithError((short) 2, (short) 47);
        }
        byte[] readFully = TlsUtils.readFully(32, (InputStream) byteArrayInputStream);
        if (TlsUtils.readOpaque8(byteArrayInputStream).length > 32) {
            failWithError((short) 2, (short) 47);
        }
        int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
        if (readUint16 < 2 || (readUint16 & 1) != 0) {
            failWithError((short) 2, (short) 50);
        }
        this.offeredCipherSuites = TlsUtils.readUint16Array(readUint16 / 2, byteArrayInputStream);
        short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
        if (readUint8 < (short) 1) {
            failWithError((short) 2, (short) 47);
        }
        this.offeredCompressionMethods = TlsUtils.readUint8Array(readUint8, byteArrayInputStream);
        this.clientExtensions = TlsProtocol.readExtensions(byteArrayInputStream);
        getContext().setClientVersion(readVersion);
        this.tlsServer.notifyClientVersion(readVersion);
        this.securityParameters.clientRandom = readFully;
        this.tlsServer.notifyOfferedCipherSuites(this.offeredCipherSuites);
        this.tlsServer.notifyOfferedCompressionMethods(this.offeredCompressionMethods);
        if (TlsProtocol.arrayContains(this.offeredCipherSuites, 255)) {
            this.secure_renegotiation = true;
        }
        if (this.clientExtensions != null) {
            byte[] bArr = (byte[]) this.clientExtensions.get(EXT_RenegotiationInfo);
            if (bArr != null) {
                this.secure_renegotiation = true;
                if (!Arrays.constantTimeAreEqual(bArr, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                    failWithError((short) 2, (short) 40);
                }
            }
        }
        this.tlsServer.notifySecureRenegotiation(this.secure_renegotiation);
        if (this.clientExtensions != null) {
            this.tlsServer.processClientExtensions(this.clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        this.keyExchange.processClientKeyExchange(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        TlsProtocol.establishMasterSecret(getContext(), this.keyExchange);
        this.recordStream.setPendingConnectionState(this.tlsServer.getCompression(), this.tlsServer.getCipher());
        if (expectCertificateVerifyMessage()) {
            this.certificateVerifyHash = this.recordStream.getCurrentHash(null);
        }
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 13, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        certificateRequest.encode(byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket) throws IOException {
        if (newSessionTicket == null) {
            throw new TlsFatalAlert((short) 80);
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 4, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        newSessionTicket.encode(byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendServerHelloDoneMessage() throws IOException {
        byte[] bArr = new byte[4];
        TlsUtils.writeUint8((short) 14, bArr, 0);
        TlsUtils.writeUint24(0, bArr, 1);
        safeWriteRecord((short) 22, bArr, 0, bArr.length);
    }

    protected void sendServerHelloMessage() throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 2, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        ProtocolVersion serverVersion = this.tlsServer.getServerVersion();
        if (!serverVersion.isEqualOrEarlierVersionOf(getContext().getClientVersion())) {
            failWithError((short) 2, (short) 80);
        }
        this.recordStream.setReadVersion(serverVersion);
        this.recordStream.setWriteVersion(serverVersion);
        this.recordStream.setRestrictReadVersion(true);
        getContext().setServerVersion(serverVersion);
        TlsUtils.writeVersion(serverVersion, byteArrayOutputStream);
        byteArrayOutputStream.write(this.securityParameters.serverRandom);
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, byteArrayOutputStream);
        this.selectedCipherSuite = this.tlsServer.getSelectedCipherSuite();
        if (!TlsProtocol.arrayContains(this.offeredCipherSuites, this.selectedCipherSuite) || this.selectedCipherSuite == 0 || this.selectedCipherSuite == 255) {
            failWithError((short) 2, (short) 80);
        }
        this.selectedCompressionMethod = this.tlsServer.getSelectedCompressionMethod();
        if (!TlsProtocol.arrayContains(this.offeredCompressionMethods, this.selectedCompressionMethod)) {
            failWithError((short) 2, (short) 80);
        }
        TlsUtils.writeUint16(this.selectedCipherSuite, byteArrayOutputStream);
        TlsUtils.writeUint8(this.selectedCompressionMethod, byteArrayOutputStream);
        this.serverExtensions = this.tlsServer.getServerExtensions();
        if (this.secure_renegotiation) {
            int i = (this.serverExtensions == null || !this.serverExtensions.containsKey(EXT_RenegotiationInfo)) ? true : 0;
            if (i != 0) {
                if (this.serverExtensions == null) {
                    this.serverExtensions = new Hashtable();
                }
                this.serverExtensions.put(EXT_RenegotiationInfo, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }
        if (this.serverExtensions != null) {
            this.expectSessionTicket = this.serverExtensions.containsKey(EXT_SessionTicket);
            TlsProtocol.writeExtensions(byteArrayOutputStream, this.serverExtensions);
        }
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendServerKeyExchangeMessage(byte[] bArr) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 12, byteArrayOutputStream);
        TlsUtils.writeUint24(bArr.length, byteArrayOutputStream);
        byteArrayOutputStream.write(bArr);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }
}
