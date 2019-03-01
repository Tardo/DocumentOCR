package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import org.bouncycastle.crypto.tls.ExporterLabel;

public class ClientHandshakeImpl extends HandshakeProtocol {

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.ClientHandshakeImpl$1 */
    class C00541 implements PrivilegedExceptionAction<Void> {
        C00541() {
        }

        public Void run() throws Exception {
            ClientHandshakeImpl.this.processServerHelloDone();
            return null;
        }
    }

    ClientHandshakeImpl(Object owner) {
        super(owner);
    }

    public void start() {
        if (this.session == null) {
            this.session = findSessionToResume();
        } else if (this.clientHello != null && this.status != 3) {
            return;
        } else {
            if (!this.session.isValid()) {
                this.session = null;
            }
        }
        if (this.session != null) {
            this.isResuming = true;
        } else if (this.parameters.getEnableSessionCreation()) {
            this.isResuming = false;
            this.session = new SSLSessionImpl(this.parameters.getSecureRandom());
            this.session.protocol = ProtocolVersion.getLatestVersion(this.parameters.getEnabledProtocols());
            this.recordProtocol.setVersion(this.session.protocol.version);
        } else {
            fatalAlert((byte) 40, "SSL Session may not be created ");
        }
        startSession();
    }

    private void renegotiateNewSession() {
        if (this.parameters.getEnableSessionCreation()) {
            this.isResuming = false;
            this.session = new SSLSessionImpl(this.parameters.getSecureRandom());
            this.session.protocol = ProtocolVersion.getLatestVersion(this.parameters.getEnabledProtocols());
            this.recordProtocol.setVersion(this.session.protocol.version);
            startSession();
            return;
        }
        this.status = 2;
        sendWarningAlert((byte) 100);
    }

    private void startSession() {
        this.clientHello = new ClientHello(this.parameters.getSecureRandom(), this.session.protocol.version, this.session.id, this.isResuming ? new CipherSuite[]{this.session.cipherSuite} : this.parameters.enabledCipherSuites);
        this.session.clientRandom = this.clientHello.random;
        send(this.clientHello);
        this.status = 1;
    }

    public void unwrap(byte[] bytes) {
        if (this.delegatedTaskErr != null) {
            Exception e = this.delegatedTaskErr;
            this.delegatedTaskErr = null;
            fatalAlert((byte) 40, "Error in delegated task", e);
        }
        this.io_stream.append(bytes);
        while (this.io_stream.available() > 0) {
            this.io_stream.mark();
            try {
                int handshakeType = this.io_stream.read();
                int length = this.io_stream.readUint24();
                if (this.io_stream.available() < length) {
                    this.io_stream.reset();
                    return;
                }
                switch (handshakeType) {
                    case 0:
                        this.io_stream.removeFromMarkedPosition();
                        if (this.clientHello == null || !(this.clientFinished == null || this.serverFinished == null)) {
                            if (!this.session.isValid()) {
                                renegotiateNewSession();
                                break;
                            }
                            this.session = (SSLSessionImpl) this.session.clone();
                            this.isResuming = true;
                            startSession();
                            break;
                        }
                    case 2:
                        if (this.clientHello == null || this.serverHello != null) {
                            unexpectedMessage();
                            return;
                        }
                        CipherSuite[] enabledSuites;
                        this.serverHello = new ServerHello(this.io_stream, length);
                        ProtocolVersion servProt = ProtocolVersion.getByVersion(this.serverHello.server_version);
                        String[] enabled = this.parameters.getEnabledProtocols();
                        int i = 0;
                        while (i < enabled.length) {
                            if (servProt.equals(ProtocolVersion.getByName(enabled[i]))) {
                                if (this.serverHello.compression_method != (byte) 0) {
                                    fatalAlert((byte) 40, "Bad server hello compression method");
                                }
                                enabledSuites = this.parameters.enabledCipherSuites;
                                for (Object equals : enabledSuites) {
                                    if (this.serverHello.cipher_suite.equals(equals)) {
                                        if (this.isResuming) {
                                            if (this.serverHello.session_id.length != 0) {
                                                this.isResuming = false;
                                            } else if (Arrays.equals(this.serverHello.session_id, this.clientHello.session_id)) {
                                                this.isResuming = false;
                                            } else if (this.session.protocol.equals(servProt)) {
                                                fatalAlert((byte) 40, "Bad server hello protocol version");
                                            } else if (!this.session.cipherSuite.equals(this.serverHello.cipher_suite)) {
                                                fatalAlert((byte) 40, "Bad server hello cipher suite");
                                            }
                                            if (this.serverHello.server_version[1] != (byte) 1) {
                                                computerReferenceVerifyDataTLS(ExporterLabel.server_finished);
                                            } else {
                                                computerReferenceVerifyDataSSLv3(SSLv3Constants.server);
                                            }
                                        }
                                        this.session.protocol = servProt;
                                        this.recordProtocol.setVersion(this.session.protocol.version);
                                        this.session.cipherSuite = this.serverHello.cipher_suite;
                                        this.session.id = (byte[]) this.serverHello.session_id.clone();
                                        this.session.serverRandom = this.serverHello.random;
                                        break;
                                    }
                                }
                                fatalAlert((byte) 40, "Bad server hello cipher suite");
                                if (this.isResuming) {
                                    if (this.serverHello.session_id.length != 0) {
                                        this.isResuming = false;
                                    } else if (Arrays.equals(this.serverHello.session_id, this.clientHello.session_id)) {
                                        this.isResuming = false;
                                    } else if (this.session.protocol.equals(servProt)) {
                                        fatalAlert((byte) 40, "Bad server hello protocol version");
                                    } else if (this.session.cipherSuite.equals(this.serverHello.cipher_suite)) {
                                        fatalAlert((byte) 40, "Bad server hello cipher suite");
                                    }
                                    if (this.serverHello.server_version[1] != (byte) 1) {
                                        computerReferenceVerifyDataSSLv3(SSLv3Constants.server);
                                    } else {
                                        computerReferenceVerifyDataTLS(ExporterLabel.server_finished);
                                    }
                                }
                                this.session.protocol = servProt;
                                this.recordProtocol.setVersion(this.session.protocol.version);
                                this.session.cipherSuite = this.serverHello.cipher_suite;
                                this.session.id = (byte[]) this.serverHello.session_id.clone();
                                this.session.serverRandom = this.serverHello.random;
                            } else {
                                i++;
                            }
                        }
                        fatalAlert((byte) 40, "Bad server hello protocol version");
                        if (this.serverHello.compression_method != (byte) 0) {
                            fatalAlert((byte) 40, "Bad server hello compression method");
                        }
                        enabledSuites = this.parameters.enabledCipherSuites;
                        while (i < enabledSuites.length) {
                            if (this.serverHello.cipher_suite.equals(equals)) {
                                if (this.isResuming) {
                                    if (this.serverHello.session_id.length != 0) {
                                        this.isResuming = false;
                                    } else if (Arrays.equals(this.serverHello.session_id, this.clientHello.session_id)) {
                                        this.isResuming = false;
                                    } else if (this.session.protocol.equals(servProt)) {
                                        fatalAlert((byte) 40, "Bad server hello protocol version");
                                    } else if (this.session.cipherSuite.equals(this.serverHello.cipher_suite)) {
                                        fatalAlert((byte) 40, "Bad server hello cipher suite");
                                    }
                                    if (this.serverHello.server_version[1] != (byte) 1) {
                                        computerReferenceVerifyDataTLS(ExporterLabel.server_finished);
                                    } else {
                                        computerReferenceVerifyDataSSLv3(SSLv3Constants.server);
                                    }
                                }
                                this.session.protocol = servProt;
                                this.recordProtocol.setVersion(this.session.protocol.version);
                                this.session.cipherSuite = this.serverHello.cipher_suite;
                                this.session.id = (byte[]) this.serverHello.session_id.clone();
                                this.session.serverRandom = this.serverHello.random;
                            } else {
                            }
                        }
                        fatalAlert((byte) 40, "Bad server hello cipher suite");
                        if (this.isResuming) {
                            if (this.serverHello.session_id.length != 0) {
                                this.isResuming = false;
                            } else if (Arrays.equals(this.serverHello.session_id, this.clientHello.session_id)) {
                                this.isResuming = false;
                            } else if (this.session.protocol.equals(servProt)) {
                                fatalAlert((byte) 40, "Bad server hello protocol version");
                            } else if (this.session.cipherSuite.equals(this.serverHello.cipher_suite)) {
                                fatalAlert((byte) 40, "Bad server hello cipher suite");
                            }
                            if (this.serverHello.server_version[1] != (byte) 1) {
                                computerReferenceVerifyDataSSLv3(SSLv3Constants.server);
                            } else {
                                computerReferenceVerifyDataTLS(ExporterLabel.server_finished);
                            }
                        }
                        this.session.protocol = servProt;
                        this.recordProtocol.setVersion(this.session.protocol.version);
                        this.session.cipherSuite = this.serverHello.cipher_suite;
                        this.session.id = (byte[]) this.serverHello.session_id.clone();
                        this.session.serverRandom = this.serverHello.random;
                        break;
                    case 11:
                        if (this.serverHello != null && this.serverKeyExchange == null && this.serverCert == null && !this.isResuming) {
                            this.serverCert = new CertificateMessage(this.io_stream, length);
                            break;
                        } else {
                            unexpectedMessage();
                            return;
                        }
                        break;
                    case 12:
                        if (this.serverHello != null && this.serverKeyExchange == null && !this.isResuming) {
                            this.serverKeyExchange = new ServerKeyExchange(this.io_stream, length, this.session.cipherSuite.keyExchange);
                            break;
                        } else {
                            unexpectedMessage();
                            return;
                        }
                        break;
                    case 13:
                        if (this.serverCert != null && this.certificateRequest == null && !this.session.cipherSuite.isAnonymous() && !this.isResuming) {
                            this.certificateRequest = new CertificateRequest(this.io_stream, length);
                            break;
                        } else {
                            unexpectedMessage();
                            return;
                        }
                        break;
                    case 14:
                        if (this.serverHello != null && this.serverHelloDone == null && !this.isResuming) {
                            this.serverHelloDone = new ServerHelloDone(this.io_stream, length);
                            if (!this.nonBlocking) {
                                processServerHelloDone();
                                break;
                            } else {
                                this.delegatedTasks.add(new DelegatedTask(new C00541(), this, AccessController.getContext()));
                                return;
                            }
                        }
                        unexpectedMessage();
                        return;
                    case 20:
                        if (this.changeCipherSpecReceived) {
                            this.serverFinished = new Finished(this.io_stream, length);
                            verifyFinished(this.serverFinished.getData());
                            this.session.lastAccessedTime = System.currentTimeMillis();
                            this.parameters.getClientSessionContext().putSession(this.session);
                            if (!this.isResuming) {
                                this.session.lastAccessedTime = System.currentTimeMillis();
                                this.status = 3;
                                break;
                            }
                            sendChangeCipherSpec();
                            break;
                        }
                        unexpectedMessage();
                        return;
                    default:
                        unexpectedMessage();
                        return;
                }
            } catch (IOException e2) {
                this.io_stream.reset();
                return;
            }
        }
    }

    public void unwrapSSLv2(byte[] bytes) {
        unexpectedMessage();
    }

    protected void makeFinished() {
        byte[] verify_data;
        if (this.serverHello.server_version[1] == (byte) 1) {
            verify_data = new byte[12];
            computerVerifyDataTLS(ExporterLabel.client_finished, verify_data);
        } else {
            verify_data = new byte[36];
            computerVerifyDataSSLv3(SSLv3Constants.client, verify_data);
        }
        this.clientFinished = new Finished(verify_data);
        send(this.clientFinished);
        if (this.isResuming) {
            this.session.lastAccessedTime = System.currentTimeMillis();
            this.status = 3;
            return;
        }
        if (this.serverHello.server_version[1] == (byte) 1) {
            computerReferenceVerifyDataTLS(ExporterLabel.server_finished);
        } else {
            computerReferenceVerifyDataSSLv3(SSLv3Constants.server);
        }
        this.status = 1;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void processServerHelloDone() {
        /*
        r28 = this;
        r8 = 0;
        r0 = r28;
        r0 = r0.serverCert;
        r23 = r0;
        if (r23 == 0) goto L_0x027d;
    L_0x0009:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DH_anon;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x003d;
    L_0x0023:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DH_anon_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x0041;
    L_0x003d:
        r28.unexpectedMessage();
    L_0x0040:
        return;
    L_0x0041:
        r28.verifyServerCert();
    L_0x0044:
        r0 = r28;
        r0 = r0.certificateRequest;
        r23 = r0;
        if (r23 == 0) goto L_0x00b3;
    L_0x004c:
        r6 = 0;
        r0 = r28;
        r0 = r0.parameters;
        r23 = r0;
        r23 = r23.getKeyManager();
        r23 = (javax.net.ssl.X509ExtendedKeyManager) r23;
        r0 = r28;
        r0 = r0.certificateRequest;
        r24 = r0;
        r24 = r24.getTypesAsString();
        r0 = r28;
        r0 = r0.certificateRequest;
        r25 = r0;
        r0 = r25;
        r0 = r0.certificate_authorities;
        r25 = r0;
        r26 = 0;
        r7 = r23.chooseClientAlias(r24, r25, r26);
        if (r7 == 0) goto L_0x008f;
    L_0x0077:
        r0 = r28;
        r0 = r0.parameters;
        r23 = r0;
        r16 = r23.getKeyManager();
        r16 = (javax.net.ssl.X509ExtendedKeyManager) r16;
        r0 = r16;
        r6 = r0.getCertificateChain(r7);
        r0 = r16;
        r8 = r0.getPrivateKey(r7);
    L_0x008f:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0.localCertificates = r6;
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.CertificateMessage;
        r0 = r23;
        r0.<init>(r6);
        r0 = r23;
        r1 = r28;
        r1.clientCert = r0;
        r0 = r28;
        r0 = r0.clientCert;
        r23 = r0;
        r0 = r28;
        r1 = r23;
        r0.send(r1);
    L_0x00b3:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x00e7;
    L_0x00cd:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x02f9;
    L_0x00e7:
        r23 = "RSA/ECB/PKCS1Padding";
        r5 = javax.crypto.Cipher.getInstance(r23);	 Catch:{ Exception -> 0x02d5 }
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x02d5 }
        r23 = r0;
        if (r23 == 0) goto L_0x02b6;
    L_0x00f5:
        r23 = 1;
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x02d5 }
        r24 = r0;
        r24 = r24.getRSAPublicKey();	 Catch:{ Exception -> 0x02d5 }
        r0 = r23;
        r1 = r24;
        r5.init(r0, r1);	 Catch:{ Exception -> 0x02d5 }
    L_0x0108:
        r23 = 48;
        r0 = r23;
        r0 = new byte[r0];
        r23 = r0;
        r0 = r23;
        r1 = r28;
        r1.preMasterSecret = r0;
        r0 = r28;
        r0 = r0.parameters;
        r23 = r0;
        r23 = r23.getSecureRandom();
        r0 = r28;
        r0 = r0.preMasterSecret;
        r24 = r0;
        r23.nextBytes(r24);
        r0 = r28;
        r0 = r0.clientHello;
        r23 = r0;
        r0 = r23;
        r0 = r0.client_version;
        r23 = r0;
        r24 = 0;
        r0 = r28;
        r0 = r0.preMasterSecret;
        r25 = r0;
        r26 = 0;
        r27 = 2;
        java.lang.System.arraycopy(r23, r24, r25, r26, r27);
        r24 = new custom.org.apache.harmony.xnet.provider.jsse.ClientKeyExchange;	 Catch:{ Exception -> 0x02e9 }
        r0 = r28;
        r0 = r0.preMasterSecret;	 Catch:{ Exception -> 0x02e9 }
        r23 = r0;
        r0 = r23;
        r25 = r5.doFinal(r0);	 Catch:{ Exception -> 0x02e9 }
        r0 = r28;
        r0 = r0.serverHello;	 Catch:{ Exception -> 0x02e9 }
        r23 = r0;
        r0 = r23;
        r0 = r0.server_version;	 Catch:{ Exception -> 0x02e9 }
        r23 = r0;
        r26 = 1;
        r23 = r23[r26];	 Catch:{ Exception -> 0x02e9 }
        r26 = 1;
        r0 = r23;
        r1 = r26;
        if (r0 != r1) goto L_0x02e5;
    L_0x016a:
        r23 = 1;
    L_0x016c:
        r0 = r24;
        r1 = r25;
        r2 = r23;
        r0.<init>(r1, r2);	 Catch:{ Exception -> 0x02e9 }
        r0 = r24;
        r1 = r28;
        r1.clientKeyExchange = r0;	 Catch:{ Exception -> 0x02e9 }
    L_0x017b:
        r0 = r28;
        r0 = r0.clientKeyExchange;
        r23 = r0;
        if (r23 == 0) goto L_0x0190;
    L_0x0183:
        r0 = r28;
        r0 = r0.clientKeyExchange;
        r23 = r0;
        r0 = r28;
        r1 = r23;
        r0.send(r1);
    L_0x0190:
        r28.computerMasterSecret();
        r0 = r28;
        r0 = r0.clientCert;
        r23 = r0;
        if (r23 == 0) goto L_0x0278;
    L_0x019b:
        r0 = r28;
        r0 = r0.clientKeyExchange;
        r23 = r0;
        r23 = r23.isEmpty();
        if (r23 != 0) goto L_0x0278;
    L_0x01a7:
        r0 = r8 instanceof es.gob.jmulticard.jse.provider.DniePrivateKey;
        r23 = r0;
        if (r23 != 0) goto L_0x01b3;
    L_0x01ad:
        r0 = r8 instanceof es.gob.jmulticard.jse.provider.MrtdPrivateKey;
        r23 = r0;
        if (r23 == 0) goto L_0x0512;
    L_0x01b3:
        r4 = new java.io.ByteArrayOutputStream;	 Catch:{ Exception -> 0x04f4 }
        r4.<init>();	 Catch:{ Exception -> 0x04f4 }
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA_EXPORT;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0220;
    L_0x01d2:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0220;
    L_0x01ec:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_RSA;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0220;
    L_0x0206:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_RSA_EXPORT;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x04af;
    L_0x0220:
        r0 = r28;
        r0 = r0.io_stream;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r23 = r23.getDigestMD5();	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r4.write(r0);	 Catch:{ Exception -> 0x04f4 }
        r0 = r28;
        r0 = r0.io_stream;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r23 = r23.getDigestSHA();	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r4.write(r0);	 Catch:{ Exception -> 0x04f4 }
    L_0x023e:
        r10 = r4.toByteArray();	 Catch:{ Exception -> 0x04f4 }
        r21 = 0;
        r0 = r8 instanceof es.gob.jmulticard.jse.provider.DniePrivateKey;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        if (r23 == 0) goto L_0x0508;
    L_0x024a:
        r23 = "NONEwithRSA";
        r24 = "DNIeJCAProvider";
        r21 = java.security.Signature.getInstance(r23, r24);	 Catch:{ Exception -> 0x04f4 }
    L_0x0252:
        r0 = r21;
        r0.initSign(r8);	 Catch:{ Exception -> 0x04f4 }
        r0 = r21;
        r0.update(r10);	 Catch:{ Exception -> 0x04f4 }
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.CertificateVerify;	 Catch:{ Exception -> 0x04f4 }
        r24 = r21.sign();	 Catch:{ Exception -> 0x04f4 }
        r23.<init>(r24);	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r28;
        r1.certificateVerify = r0;	 Catch:{ Exception -> 0x04f4 }
    L_0x026b:
        r0 = r28;
        r0 = r0.certificateVerify;
        r23 = r0;
        r0 = r28;
        r1 = r23;
        r0.send(r1);
    L_0x0278:
        r28.sendChangeCipherSpec();
        goto L_0x0040;
    L_0x027d:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DH_anon;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0044;
    L_0x0297:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DH_anon_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0044;
    L_0x02b1:
        r28.unexpectedMessage();
        goto L_0x0040;
    L_0x02b6:
        r23 = 1;
        r0 = r28;
        r0 = r0.serverCert;	 Catch:{ Exception -> 0x02d5 }
        r24 = r0;
        r0 = r24;
        r0 = r0.certs;	 Catch:{ Exception -> 0x02d5 }
        r24 = r0;
        r25 = 0;
        r24 = r24[r25];	 Catch:{ Exception -> 0x02d5 }
        r24 = r24.getPublicKey();	 Catch:{ Exception -> 0x02d5 }
        r0 = r23;
        r1 = r24;
        r5.init(r0, r1);	 Catch:{ Exception -> 0x02d5 }
        goto L_0x0108;
    L_0x02d5:
        r12 = move-exception;
        r23 = 80;
        r24 = "Unexpected exception";
        r0 = r28;
        r1 = r23;
        r2 = r24;
        r0.fatalAlert(r1, r2, r12);
        goto L_0x0040;
    L_0x02e5:
        r23 = 0;
        goto L_0x016c;
    L_0x02e9:
        r12 = move-exception;
        r23 = 80;
        r24 = "Unexpected exception";
        r0 = r28;
        r1 = r23;
        r2 = r24;
        r0.fatalAlert(r1, r2, r12);
        goto L_0x0040;
    L_0x02f9:
        r3 = 0;
        r15 = 0;
        r23 = "DH";
        r15 = java.security.KeyFactory.getInstance(r23);	 Catch:{ NoSuchAlgorithmException -> 0x0462 }
    L_0x0301:
        r23 = "DH";
        r3 = javax.crypto.KeyAgreement.getInstance(r23);	 Catch:{ NoSuchAlgorithmException -> 0x046b }
    L_0x0307:
        r18 = 0;
        r23 = "DH";
        r18 = java.security.KeyPairGenerator.getInstance(r23);	 Catch:{ NoSuchAlgorithmException -> 0x0474 }
    L_0x030f:
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        if (r23 == 0) goto L_0x047d;
    L_0x0317:
        r23 = new javax.crypto.spec.DHPublicKeySpec;	 Catch:{ Exception -> 0x0452 }
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r24 = r0;
        r0 = r24;
        r0 = r0.par3;	 Catch:{ Exception -> 0x0452 }
        r24 = r0;
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r25 = r0;
        r0 = r25;
        r0 = r0.par1;	 Catch:{ Exception -> 0x0452 }
        r25 = r0;
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r26 = r0;
        r0 = r26;
        r0 = r0.par2;	 Catch:{ Exception -> 0x0452 }
        r26 = r0;
        r23.<init>(r24, r25, r26);	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r19 = r15.generatePublic(r0);	 Catch:{ Exception -> 0x0452 }
        r22 = new javax.crypto.spec.DHParameterSpec;	 Catch:{ Exception -> 0x0452 }
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.par1;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r28;
        r0 = r0.serverKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r24 = r0;
        r0 = r24;
        r0 = r0.par2;	 Catch:{ Exception -> 0x0452 }
        r24 = r0;
        r22.<init>(r23, r24);	 Catch:{ Exception -> 0x0452 }
    L_0x0363:
        r0 = r18;
        r1 = r22;
        r0.initialize(r1);	 Catch:{ Exception -> 0x0452 }
        r17 = r18.generateKeyPair();	 Catch:{ Exception -> 0x0452 }
        r14 = r17.getPublic();	 Catch:{ Exception -> 0x0452 }
        r0 = r28;
        r0 = r0.clientCert;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        if (r23 == 0) goto L_0x049d;
    L_0x037a:
        r0 = r28;
        r0 = r0.serverCert;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        if (r23 == 0) goto L_0x049d;
    L_0x0382:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_RSA;	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x03b6;
    L_0x039c:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_DSS;	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x049d;
    L_0x03b6:
        r0 = r28;
        r0 = r0.clientCert;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.certs;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r24 = 0;
        r23 = r23[r24];	 Catch:{ Exception -> 0x0452 }
        r9 = r23.getPublicKey();	 Catch:{ Exception -> 0x0452 }
        r0 = r28;
        r0 = r0.serverCert;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.certs;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r24 = 0;
        r23 = r23[r24];	 Catch:{ Exception -> 0x0452 }
        r20 = r23.getPublicKey();	 Catch:{ Exception -> 0x0452 }
        r0 = r9 instanceof javax.crypto.interfaces.DHKey;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        if (r23 == 0) goto L_0x0436;
    L_0x03e4:
        r0 = r20;
        r0 = r0 instanceof javax.crypto.interfaces.DHKey;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        if (r23 == 0) goto L_0x0436;
    L_0x03ec:
        r0 = r9;
        r0 = (javax.crypto.interfaces.DHKey) r0;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r23 = r23.getParams();	 Catch:{ Exception -> 0x0452 }
        r24 = r23.getG();	 Catch:{ Exception -> 0x0452 }
        r0 = r20;
        r0 = (javax.crypto.interfaces.DHKey) r0;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r23 = r23.getParams();	 Catch:{ Exception -> 0x0452 }
        r23 = r23.getG();	 Catch:{ Exception -> 0x0452 }
        r0 = r24;
        r1 = r23;
        r23 = r0.equals(r1);	 Catch:{ Exception -> 0x0452 }
        if (r23 == 0) goto L_0x0436;
    L_0x0411:
        r9 = (javax.crypto.interfaces.DHKey) r9;	 Catch:{ Exception -> 0x0452 }
        r23 = r9.getParams();	 Catch:{ Exception -> 0x0452 }
        r23 = r23.getP();	 Catch:{ Exception -> 0x0452 }
        r20 = (javax.crypto.interfaces.DHKey) r20;	 Catch:{ Exception -> 0x0452 }
        r24 = r20.getParams();	 Catch:{ Exception -> 0x0452 }
        r24 = r24.getG();	 Catch:{ Exception -> 0x0452 }
        r23 = r23.equals(r24);	 Catch:{ Exception -> 0x0452 }
        if (r23 == 0) goto L_0x0436;
    L_0x042b:
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.ClientKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r23.<init>();	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r1 = r28;
        r1.clientKeyExchange = r0;	 Catch:{ Exception -> 0x0452 }
    L_0x0436:
        r14 = r17.getPrivate();	 Catch:{ Exception -> 0x0452 }
        r3.init(r14);	 Catch:{ Exception -> 0x0452 }
        r23 = 1;
        r0 = r19;
        r1 = r23;
        r3.doPhase(r0, r1);	 Catch:{ Exception -> 0x0452 }
        r23 = r3.generateSecret();	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r1 = r28;
        r1.preMasterSecret = r0;	 Catch:{ Exception -> 0x0452 }
        goto L_0x017b;
    L_0x0452:
        r12 = move-exception;
        r23 = 80;
        r24 = "Unexpected exception";
        r0 = r28;
        r1 = r23;
        r2 = r24;
        r0.fatalAlert(r1, r2, r12);
        goto L_0x0040;
    L_0x0462:
        r12 = move-exception;
        r23 = "DiffieHellman";
        r15 = java.security.KeyFactory.getInstance(r23);	 Catch:{ Exception -> 0x0452 }
        goto L_0x0301;
    L_0x046b:
        r13 = move-exception;
        r23 = "DiffieHellman";
        r3 = javax.crypto.KeyAgreement.getInstance(r23);	 Catch:{ Exception -> 0x0452 }
        goto L_0x0307;
    L_0x0474:
        r12 = move-exception;
        r23 = "DiffieHellman";
        r18 = java.security.KeyPairGenerator.getInstance(r23);	 Catch:{ Exception -> 0x0452 }
        goto L_0x030f;
    L_0x047d:
        r0 = r28;
        r0 = r0.serverCert;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r0 = r23;
        r0 = r0.certs;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r24 = 0;
        r23 = r23[r24];	 Catch:{ Exception -> 0x0452 }
        r19 = r23.getPublicKey();	 Catch:{ Exception -> 0x0452 }
        r0 = r19;
        r0 = (javax.crypto.interfaces.DHPublicKey) r0;	 Catch:{ Exception -> 0x0452 }
        r23 = r0;
        r22 = r23.getParams();	 Catch:{ Exception -> 0x0452 }
        goto L_0x0363;
    L_0x049d:
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.ClientKeyExchange;	 Catch:{ Exception -> 0x0452 }
        r14 = (javax.crypto.interfaces.DHPublicKey) r14;	 Catch:{ Exception -> 0x0452 }
        r24 = r14.getY();	 Catch:{ Exception -> 0x0452 }
        r23.<init>(r24);	 Catch:{ Exception -> 0x0452 }
        r0 = r23;
        r1 = r28;
        r1.clientKeyExchange = r0;	 Catch:{ Exception -> 0x0452 }
        goto L_0x0436;
    L_0x04af:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_DSS;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x04e3;
    L_0x04c9:
        r0 = r28;
        r0 = r0.session;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_DSS_EXPORT;	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x023e;
    L_0x04e3:
        r0 = r28;
        r0 = r0.io_stream;	 Catch:{ Exception -> 0x04f4 }
        r23 = r0;
        r23 = r23.getDigestSHA();	 Catch:{ Exception -> 0x04f4 }
        r0 = r23;
        r4.write(r0);	 Catch:{ Exception -> 0x04f4 }
        goto L_0x023e;
    L_0x04f4:
        r12 = move-exception;
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.AlertException;
        r24 = 42;
        r25 = new javax.net.ssl.SSLException;
        r26 = "init - invalid certificate";
        r0 = r25;
        r1 = r26;
        r0.<init>(r1, r12);
        r23.<init>(r24, r25);
        throw r23;
    L_0x0508:
        r23 = "MRTDNONEwithRSA";
        r24 = "DNIeJCAProvider";
        r21 = java.security.Signature.getInstance(r23, r24);	 Catch:{ Exception -> 0x04f4 }
        goto L_0x0252;
    L_0x0512:
        r11 = new custom.org.apache.harmony.xnet.provider.jsse.DigitalSignature;
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r0 = r23;
        r11.<init>(r0);
        r11.init(r8);
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0596;
    L_0x0548:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_RSA;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0596;
    L_0x0562:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_RSA;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x0596;
    L_0x057c:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_RSA_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x05c5;
    L_0x0596:
        r0 = r28;
        r0 = r0.io_stream;
        r23 = r0;
        r23 = r23.getDigestMD5();
        r0 = r23;
        r11.setMD5(r0);
        r0 = r28;
        r0 = r0.io_stream;
        r23 = r0;
        r23 = r23.getDigestSHA();
        r0 = r23;
        r11.setSHA(r0);
    L_0x05b4:
        r23 = new custom.org.apache.harmony.xnet.provider.jsse.CertificateVerify;
        r24 = r11.sign();
        r23.<init>(r24);
        r0 = r23;
        r1 = r28;
        r1.certificateVerify = r0;
        goto L_0x026b;
    L_0x05c5:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_DSS;
        r0 = r23;
        r1 = r24;
        if (r0 == r1) goto L_0x05f9;
    L_0x05df:
        r0 = r28;
        r0 = r0.session;
        r23 = r0;
        r0 = r23;
        r0 = r0.cipherSuite;
        r23 = r0;
        r0 = r23;
        r0 = r0.keyExchange;
        r23 = r0;
        r24 = custom.org.apache.harmony.xnet.provider.jsse.CipherSuite.KeyExchange_DHE_DSS_EXPORT;
        r0 = r23;
        r1 = r24;
        if (r0 != r1) goto L_0x05b4;
    L_0x05f9:
        r0 = r28;
        r0 = r0.io_stream;
        r23 = r0;
        r23 = r23.getDigestSHA();
        r0 = r23;
        r11.setSHA(r0);
        goto L_0x05b4;
        */
        throw new UnsupportedOperationException("Method not decompiled: custom.org.apache.harmony.xnet.provider.jsse.ClientHandshakeImpl.processServerHelloDone():void");
    }

    private void verifyServerCert() {
        String authType = null;
        switch (this.session.cipherSuite.keyExchange) {
            case 1:
                authType = "RSA";
                break;
            case 2:
                if (this.serverKeyExchange == null) {
                    authType = "RSA";
                    break;
                } else {
                    authType = "RSA_EXPORT";
                    break;
                }
            case 3:
            case 4:
                authType = "DHE_DSS";
                break;
            case 5:
            case 6:
                authType = "DHE_RSA";
                break;
            case 7:
            case 11:
                authType = "DH_DSS";
                break;
            case 8:
            case 12:
                authType = "DH_RSA";
                break;
            case 9:
            case 10:
                return;
        }
        try {
            this.parameters.getTrustManager().checkServerTrusted(this.serverCert.certs, authType);
            this.session.peerCertificates = this.serverCert.certs;
        } catch (CertificateException e) {
            fatalAlert((byte) 42, "Not trusted server certificate", e);
        }
    }

    public void receiveChangeCipherSpec() {
        if (this.isResuming) {
            if (this.serverHello == null) {
                unexpectedMessage();
            }
        } else if (this.clientFinished == null) {
            unexpectedMessage();
        }
        this.changeCipherSpecReceived = true;
    }

    private SSLSessionImpl findSessionToResume() {
        String host;
        int port;
        if (this.engineOwner != null) {
            host = this.engineOwner.getPeerHost();
            port = this.engineOwner.getPeerPort();
        } else {
            host = this.socketOwner.getInetAddress().getHostName();
            port = this.socketOwner.getPort();
        }
        if (host == null || port == -1) {
            return null;
        }
        SSLSessionContext context = this.parameters.getClientSessionContext();
        Enumeration<?> en = context.getIds();
        while (en.hasMoreElements()) {
            SSLSession ses = context.getSession((byte[]) en.nextElement());
            if (host.equals(ses.getPeerHost()) && port == ses.getPeerPort()) {
                return (SSLSessionImpl) ((SSLSessionImpl) ses).clone();
            }
        }
        return null;
    }
}
