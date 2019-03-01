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
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.util.Arrays;

public class TlsClientProtocol extends TlsProtocol {
    protected TlsAuthentication authentication;
    protected CertificateRequest certificateRequest;
    protected Hashtable clientExtensions;
    protected TlsKeyExchange keyExchange;
    protected int[] offeredCipherSuites;
    protected short[] offeredCompressionMethods;
    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected TlsClient tlsClient;
    protected TlsClientContextImpl tlsClientContext;

    public TlsClientProtocol(InputStream inputStream, OutputStream outputStream) {
        this(inputStream, outputStream, createSecureRandom());
    }

    public TlsClientProtocol(InputStream inputStream, OutputStream outputStream, SecureRandom secureRandom) {
        super(inputStream, outputStream, secureRandom);
        this.tlsClient = null;
        this.tlsClientContext = null;
        this.offeredCipherSuites = null;
        this.offeredCompressionMethods = null;
        this.clientExtensions = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateRequest = null;
    }

    private static SecureRandom createSecureRandom() {
        ThreadedSeedGenerator threadedSeedGenerator = new ThreadedSeedGenerator();
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(threadedSeedGenerator.generateSeed(20, true));
        return secureRandom;
    }

    public void connect(TlsClient tlsClient) throws IOException {
        if (tlsClient == null) {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        } else if (this.tlsClient != null) {
            throw new IllegalStateException("connect can only be called once");
        } else {
            this.tlsClient = tlsClient;
            this.securityParameters = new SecurityParameters();
            this.securityParameters.entity = 1;
            this.securityParameters.clientRandom = TlsProtocol.createRandomBlock(this.secureRandom);
            this.tlsClientContext = new TlsClientContextImpl(this.secureRandom, this.securityParameters);
            this.tlsClient.init(this.tlsClientContext);
            this.recordStream.init(this.tlsClientContext);
            sendClientHelloMessage();
            this.connection_state = (short) 1;
            completeHandshake();
            this.tlsClient.notifyHandshakeComplete();
        }
    }

    protected AbstractTlsContext getContext() {
        return this.tlsClientContext;
    }

    protected TlsPeer getPeer() {
        return this.tlsClient;
    }

    protected void handleChangeCipherSpecMessage() throws IOException {
        switch (this.connection_state) {
            case (short) 13:
                if (this.expectSessionTicket) {
                    failWithError((short) 2, (short) 40);
                    break;
                }
                break;
            case (short) 14:
                break;
            default:
                failWithError((short) 2, (short) 40);
                return;
        }
        this.connection_state = (short) 15;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    protected void handleHandshakeMessage(short r8, byte[] r9) throws java.io.IOException {
        /*
        r7 = this;
        r2 = 16;
        r6 = 12;
        r1 = 0;
        r5 = 10;
        r3 = 2;
        r0 = new java.io.ByteArrayInputStream;
        r0.<init>(r9);
        switch(r8) {
            case 0: goto L_0x017e;
            case 2: goto L_0x004c;
            case 4: goto L_0x0176;
            case 11: goto L_0x0014;
            case 12: goto L_0x012a;
            case 13: goto L_0x014a;
            case 14: goto L_0x0085;
            case 20: goto L_0x003d;
            case 23: goto L_0x0074;
            default: goto L_0x0010;
        };
    L_0x0010:
        r7.failWithError(r3, r5);
    L_0x0013:
        return;
    L_0x0014:
        r2 = r7.connection_state;
        switch(r2) {
            case 2: goto L_0x0020;
            case 3: goto L_0x0023;
            default: goto L_0x0019;
        };
    L_0x0019:
        r7.failWithError(r3, r5);
    L_0x001c:
        r0 = 4;
        r7.connection_state = r0;
        goto L_0x0013;
    L_0x0020:
        r7.handleSupplementalData(r1);
    L_0x0023:
        r1 = org.bouncycastle.crypto.tls.Certificate.parse(r0);
        org.bouncycastle.crypto.tls.TlsProtocol.assertEmpty(r0);
        r0 = r7.keyExchange;
        r0.processServerCertificate(r1);
        r0 = r7.tlsClient;
        r0 = r0.getAuthentication();
        r7.authentication = r0;
        r0 = r7.authentication;
        r0.notifyServerCertificate(r1);
        goto L_0x001c;
    L_0x003d:
        r1 = r7.connection_state;
        switch(r1) {
            case 15: goto L_0x0046;
            default: goto L_0x0042;
        };
    L_0x0042:
        r7.failWithError(r3, r5);
        goto L_0x0013;
    L_0x0046:
        r7.processFinishedMessage(r0);
        r7.connection_state = r2;
        goto L_0x0013;
    L_0x004c:
        r1 = r7.connection_state;
        switch(r1) {
            case 1: goto L_0x0055;
            default: goto L_0x0051;
        };
    L_0x0051:
        r7.failWithError(r3, r5);
        goto L_0x0013;
    L_0x0055:
        r7.receiveServerHelloMessage(r0);
        r7.connection_state = r3;
        r0 = r7.securityParameters;
        r1 = r7.selectedCipherSuite;
        r1 = org.bouncycastle.crypto.tls.TlsProtocol.getPRFAlgorithm(r1);
        r0.prfAlgorithm = r1;
        r0 = r7.securityParameters;
        r1 = r7.selectedCompressionMethod;
        r0.compressionAlgorithm = r1;
        r0 = r7.securityParameters;
        r0.verifyDataLength = r6;
        r0 = r7.recordStream;
        r0.notifyHelloComplete();
        goto L_0x0013;
    L_0x0074:
        r1 = r7.connection_state;
        switch(r1) {
            case 2: goto L_0x007d;
            default: goto L_0x0079;
        };
    L_0x0079:
        r7.failWithError(r3, r5);
        goto L_0x0013;
    L_0x007d:
        r0 = org.bouncycastle.crypto.tls.TlsProtocol.readSupplementalDataMessage(r0);
        r7.handleSupplementalData(r0);
        goto L_0x0013;
    L_0x0085:
        r2 = r7.connection_state;
        switch(r2) {
            case 2: goto L_0x0090;
            case 3: goto L_0x0093;
            case 4: goto L_0x009a;
            case 5: goto L_0x009f;
            case 6: goto L_0x009f;
            default: goto L_0x008a;
        };
    L_0x008a:
        r0 = 40;
        r7.failWithError(r3, r0);
        goto L_0x0013;
    L_0x0090:
        r7.handleSupplementalData(r1);
    L_0x0093:
        r2 = r7.keyExchange;
        r2.skipServerCredentials();
        r7.authentication = r1;
    L_0x009a:
        r2 = r7.keyExchange;
        r2.skipServerKeyExchange();
    L_0x009f:
        org.bouncycastle.crypto.tls.TlsProtocol.assertEmpty(r0);
        r0 = 7;
        r7.connection_state = r0;
        r0 = r7.tlsClient;
        r0 = r0.getClientSupplementalData();
        if (r0 == 0) goto L_0x00b0;
    L_0x00ad:
        r7.sendSupplementalDataMessage(r0);
    L_0x00b0:
        r0 = 8;
        r7.connection_state = r0;
        r0 = r7.certificateRequest;
        if (r0 != 0) goto L_0x0108;
    L_0x00b8:
        r0 = r7.keyExchange;
        r0.skipClientCredentials();
        r0 = r1;
    L_0x00be:
        r2 = 9;
        r7.connection_state = r2;
        r7.sendClientKeyExchangeMessage();
        r2 = r7.getContext();
        r3 = r7.keyExchange;
        org.bouncycastle.crypto.tls.TlsProtocol.establishMasterSecret(r2, r3);
        r2 = r7.recordStream;
        r3 = r7.tlsClient;
        r3 = r3.getCompression();
        r4 = r7.tlsClient;
        r4 = r4.getCipher();
        r2.setPendingConnectionState(r3, r4);
        r7.connection_state = r5;
        if (r0 == 0) goto L_0x00fa;
    L_0x00e3:
        r2 = r0 instanceof org.bouncycastle.crypto.tls.TlsSignerCredentials;
        if (r2 == 0) goto L_0x00fa;
    L_0x00e7:
        r0 = (org.bouncycastle.crypto.tls.TlsSignerCredentials) r0;
        r2 = r7.recordStream;
        r1 = r2.getCurrentHash(r1);
        r0 = r0.generateCertificateSignature(r1);
        r7.sendCertificateVerifyMessage(r0);
        r0 = 11;
        r7.connection_state = r0;
    L_0x00fa:
        r7.sendChangeCipherSpecMessage();
        r7.connection_state = r6;
        r7.sendFinishedMessage();
        r0 = 13;
        r7.connection_state = r0;
        goto L_0x0013;
    L_0x0108:
        r0 = r7.authentication;
        r2 = r7.certificateRequest;
        r0 = r0.getClientCredentials(r2);
        if (r0 != 0) goto L_0x011d;
    L_0x0112:
        r2 = r7.keyExchange;
        r2.skipClientCredentials();
        r2 = org.bouncycastle.crypto.tls.Certificate.EMPTY_CHAIN;
        r7.sendCertificateMessage(r2);
        goto L_0x00be;
    L_0x011d:
        r2 = r7.keyExchange;
        r2.processClientCredentials(r0);
        r2 = r0.getCertificate();
        r7.sendCertificateMessage(r2);
        goto L_0x00be;
    L_0x012a:
        r2 = r7.connection_state;
        switch(r2) {
            case 2: goto L_0x0137;
            case 3: goto L_0x013a;
            case 4: goto L_0x0141;
            default: goto L_0x012f;
        };
    L_0x012f:
        r7.failWithError(r3, r5);
    L_0x0132:
        r0 = 5;
        r7.connection_state = r0;
        goto L_0x0013;
    L_0x0137:
        r7.handleSupplementalData(r1);
    L_0x013a:
        r2 = r7.keyExchange;
        r2.skipServerCredentials();
        r7.authentication = r1;
    L_0x0141:
        r1 = r7.keyExchange;
        r1.processServerKeyExchange(r0);
        org.bouncycastle.crypto.tls.TlsProtocol.assertEmpty(r0);
        goto L_0x0132;
    L_0x014a:
        r1 = r7.connection_state;
        switch(r1) {
            case 4: goto L_0x0157;
            case 5: goto L_0x015c;
            default: goto L_0x014f;
        };
    L_0x014f:
        r7.failWithError(r3, r5);
    L_0x0152:
        r0 = 6;
        r7.connection_state = r0;
        goto L_0x0013;
    L_0x0157:
        r1 = r7.keyExchange;
        r1.skipServerKeyExchange();
    L_0x015c:
        r1 = r7.authentication;
        if (r1 != 0) goto L_0x0165;
    L_0x0160:
        r1 = 40;
        r7.failWithError(r3, r1);
    L_0x0165:
        r1 = org.bouncycastle.crypto.tls.CertificateRequest.parse(r0);
        r7.certificateRequest = r1;
        org.bouncycastle.crypto.tls.TlsProtocol.assertEmpty(r0);
        r0 = r7.keyExchange;
        r1 = r7.certificateRequest;
        r0.validateCertificateRequest(r1);
        goto L_0x0152;
    L_0x0176:
        r1 = r7.connection_state;
        switch(r1) {
            case 13: goto L_0x018e;
            default: goto L_0x017b;
        };
    L_0x017b:
        r7.failWithError(r3, r5);
    L_0x017e:
        org.bouncycastle.crypto.tls.TlsProtocol.assertEmpty(r0);
        r0 = r7.connection_state;
        if (r0 != r2) goto L_0x0013;
    L_0x0185:
        r0 = "Renegotiation not supported";
        r1 = 100;
        r7.raiseWarning(r1, r0);
        goto L_0x0013;
    L_0x018e:
        r1 = r7.expectSessionTicket;
        if (r1 != 0) goto L_0x0195;
    L_0x0192:
        r7.failWithError(r3, r5);
    L_0x0195:
        r7.receiveNewSessionTicketMessage(r0);
        r1 = 14;
        r7.connection_state = r1;
        goto L_0x017e;
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.tls.TlsClientProtocol.handleHandshakeMessage(short, byte[]):void");
    }

    protected void handleSupplementalData(Vector vector) throws IOException {
        this.tlsClient.processServerSupplementalData(vector);
        this.connection_state = (short) 3;
        this.keyExchange = this.tlsClient.getKeyExchange();
        this.keyExchange.init(getContext());
    }

    protected void receiveNewSessionTicketMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        NewSessionTicket parse = NewSessionTicket.parse(byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        this.tlsClient.notifyNewSessionTicket(parse);
    }

    protected void receiveServerHelloMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        ProtocolVersion readVersion = TlsUtils.readVersion(byteArrayInputStream);
        if (readVersion.isDTLS()) {
            failWithError((short) 2, (short) 47);
        }
        if (!readVersion.equals(this.recordStream.getReadVersion())) {
            failWithError((short) 2, (short) 47);
        }
        if (!readVersion.isEqualOrEarlierVersionOf(getContext().getClientVersion())) {
            failWithError((short) 2, (short) 47);
        }
        this.recordStream.setWriteVersion(readVersion);
        getContext().setServerVersion(readVersion);
        this.tlsClient.notifyServerVersion(readVersion);
        this.securityParameters.serverRandom = TlsUtils.readFully(32, (InputStream) byteArrayInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream);
        if (readOpaque8.length > 32) {
            failWithError((short) 2, (short) 47);
        }
        this.tlsClient.notifySessionID(readOpaque8);
        this.selectedCipherSuite = TlsUtils.readUint16(byteArrayInputStream);
        if (!TlsProtocol.arrayContains(this.offeredCipherSuites, this.selectedCipherSuite) || this.selectedCipherSuite == 0 || this.selectedCipherSuite == 255) {
            failWithError((short) 2, (short) 47);
        }
        this.tlsClient.notifySelectedCipherSuite(this.selectedCipherSuite);
        short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
        if (!TlsProtocol.arrayContains(this.offeredCompressionMethods, readUint8)) {
            failWithError((short) 2, (short) 47);
        }
        this.tlsClient.notifySelectedCompressionMethod(readUint8);
        Hashtable readExtensions = TlsProtocol.readExtensions(byteArrayInputStream);
        if (readExtensions != null) {
            Enumeration keys = readExtensions.keys();
            while (keys.hasMoreElements()) {
                Integer num = (Integer) keys.nextElement();
                if (!num.equals(EXT_RenegotiationInfo) && (this.clientExtensions == null || this.clientExtensions.get(num) == null)) {
                    failWithError((short) 2, (short) 110);
                }
            }
            readOpaque8 = (byte[]) readExtensions.get(EXT_RenegotiationInfo);
            if (readOpaque8 != null) {
                this.secure_renegotiation = true;
                if (!Arrays.constantTimeAreEqual(readOpaque8, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES))) {
                    failWithError((short) 2, (short) 40);
                }
            }
            this.expectSessionTicket = readExtensions.containsKey(EXT_SessionTicket);
        }
        this.tlsClient.notifySecureRenegotiation(this.secure_renegotiation);
        if (this.clientExtensions != null) {
            this.tlsClient.processServerExtensions(readExtensions);
        }
    }

    protected void sendCertificateVerifyMessage(byte[] bArr) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 15, byteArrayOutputStream);
        TlsUtils.writeUint24(bArr.length + 2, byteArrayOutputStream);
        TlsUtils.writeOpaque16(bArr, byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendClientHelloMessage() throws IOException {
        this.recordStream.setWriteVersion(this.tlsClient.getClientHelloRecordLayerVersion());
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 1, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        ProtocolVersion clientVersion = this.tlsClient.getClientVersion();
        if (clientVersion.isDTLS()) {
            failWithError((short) 2, (short) 80);
        }
        getContext().setClientVersion(clientVersion);
        TlsUtils.writeVersion(clientVersion, byteArrayOutputStream);
        byteArrayOutputStream.write(this.securityParameters.clientRandom);
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, byteArrayOutputStream);
        this.offeredCipherSuites = this.tlsClient.getCipherSuites();
        this.clientExtensions = this.tlsClient.getClientExtensions();
        int i = (this.clientExtensions == null || this.clientExtensions.get(EXT_RenegotiationInfo) == null) ? (short) 1 : 0;
        int length = this.offeredCipherSuites.length;
        if (i != 0) {
            length++;
        }
        TlsUtils.writeUint16(length * 2, byteArrayOutputStream);
        TlsUtils.writeUint16Array(this.offeredCipherSuites, byteArrayOutputStream);
        if (i != 0) {
            TlsUtils.writeUint16(255, byteArrayOutputStream);
        }
        this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();
        TlsUtils.writeUint8((short) this.offeredCompressionMethods.length, byteArrayOutputStream);
        TlsUtils.writeUint8Array(this.offeredCompressionMethods, byteArrayOutputStream);
        if (this.clientExtensions != null) {
            TlsProtocol.writeExtensions(byteArrayOutputStream, this.clientExtensions);
        }
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendClientKeyExchangeMessage() throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 16, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        this.keyExchange.generateClientKeyExchange(byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }
}
