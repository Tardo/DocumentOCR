package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.bouncycastle.crypto.tls.ExporterLabel;

public class ServerHandshakeImpl extends HandshakeProtocol {
    private PrivateKey privKey;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.ServerHandshakeImpl$1 */
    class C00611 implements PrivilegedExceptionAction<Void> {
        C00611() {
        }

        public Void run() throws Exception {
            ServerHandshakeImpl.this.processClientHello();
            return null;
        }
    }

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.ServerHandshakeImpl$2 */
    class C00622 implements PrivilegedExceptionAction<Void> {
        C00622() {
        }

        public Void run() throws Exception {
            ServerHandshakeImpl.this.processClientHello();
            return null;
        }
    }

    public ServerHandshakeImpl(Object owner) {
        super(owner);
        this.status = 1;
    }

    public void start() {
        if (this.session == null) {
            this.status = 1;
        } else if (this.clientHello == null || this.status == 3) {
            sendHelloRequest();
            this.status = 1;
        }
    }

    public void unwrap(byte[] bytes) {
        this.io_stream.append(bytes);
        while (this.io_stream.available() > 0) {
            this.io_stream.mark();
            int handshakeType = this.io_stream.read();
            int length = this.io_stream.readUint24();
            if (this.io_stream.available() < length) {
                this.io_stream.reset();
                return;
            }
            switch (handshakeType) {
                case 1:
                    try {
                        if (this.clientHello == null || this.status == 3) {
                            this.needSendHelloRequest = false;
                            this.clientHello = new ClientHello(this.io_stream, length);
                            if (!this.nonBlocking) {
                                processClientHello();
                                break;
                            } else {
                                this.delegatedTasks.add(new DelegatedTask(new C00611(), this, AccessController.getContext()));
                                return;
                            }
                        }
                        unexpectedMessage();
                        return;
                    } catch (IOException e) {
                        this.io_stream.reset();
                        return;
                    }
                    break;
                case 11:
                    if (!this.isResuming && this.certificateRequest != null && this.serverHelloDone != null && this.clientCert == null) {
                        this.clientCert = new CertificateMessage(this.io_stream, length);
                        if (this.clientCert.certs.length == 0) {
                            if (!this.parameters.getNeedClientAuth()) {
                                break;
                            }
                            fatalAlert((byte) 40, "HANDSHAKE FAILURE: no client certificate received");
                            break;
                        }
                        try {
                            this.parameters.getTrustManager().checkClientTrusted(this.clientCert.certs, this.clientCert.certs[0].getPublicKey().getAlgorithm());
                        } catch (CertificateException e2) {
                            fatalAlert((byte) 42, "Untrusted Client Certificate ", e2);
                        }
                        this.session.peerCertificates = this.clientCert.certs;
                        break;
                    }
                    unexpectedMessage();
                    return;
                case 15:
                    if (!this.isResuming && this.clientKeyExchange != null && this.clientCert != null && !this.clientKeyExchange.isEmpty() && this.certificateVerify == null && !this.changeCipherSpecReceived) {
                        this.certificateVerify = new CertificateVerify(this.io_stream, length);
                        DigitalSignature ds = new DigitalSignature(this.session.cipherSuite.keyExchange);
                        ds.init(this.serverCert.certs[0]);
                        byte[] md5_hash = null;
                        byte[] sha_hash = null;
                        if (this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_RSA_EXPORT || this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_RSA || this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_DHE_RSA || this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_DHE_RSA_EXPORT) {
                            md5_hash = this.io_stream.getDigestMD5withoutLast();
                            sha_hash = this.io_stream.getDigestSHAwithoutLast();
                        } else {
                            if (this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_DHE_DSS || this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_DHE_DSS_EXPORT) {
                                sha_hash = this.io_stream.getDigestSHAwithoutLast();
                            } else {
                                if (this.session.cipherSuite.keyExchange != CipherSuite.KeyExchange_DH_anon && this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_DH_anon_EXPORT) {
                                }
                            }
                        }
                        ds.setMD5(md5_hash);
                        ds.setSHA(sha_hash);
                        if (!ds.verifySignature(this.certificateVerify.signedHash)) {
                            fatalAlert((byte) 51, "DECRYPT ERROR: CERTIFICATE_VERIFY incorrect signature");
                            break;
                        }
                        break;
                    }
                    unexpectedMessage();
                    return;
                    break;
                case 16:
                    if (!this.isResuming && this.serverHelloDone != null && this.clientKeyExchange == null && (this.clientCert != null || !this.parameters.getNeedClientAuth())) {
                        if (this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_RSA || this.session.cipherSuite.keyExchange == CipherSuite.KeyExchange_RSA_EXPORT) {
                            this.clientKeyExchange = new ClientKeyExchange(this.io_stream, length, this.serverHello.server_version[1] == (byte) 1, true);
                            try {
                                Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                c.init(2, this.privKey);
                                this.preMasterSecret = c.doFinal(this.clientKeyExchange.exchange_keys);
                                if (!(this.preMasterSecret.length == 48 && this.preMasterSecret[0] == this.clientHello.client_version[0] && this.preMasterSecret[1] == this.clientHello.client_version[1])) {
                                    this.preMasterSecret = new byte[48];
                                    this.parameters.getSecureRandom().nextBytes(this.preMasterSecret);
                                }
                            } catch (Exception e3) {
                                fatalAlert((byte) 80, "INTERNAL ERROR", e3);
                            }
                        } else {
                            this.clientKeyExchange = new ClientKeyExchange(this.io_stream, length, this.serverHello.server_version[1] == (byte) 1, false);
                            if (this.clientKeyExchange.isEmpty()) {
                                this.preMasterSecret = ((DHPublicKey) this.clientCert.certs[0].getPublicKey()).getY().toByteArray();
                            } else {
                                KeyFactory kf;
                                KeyAgreement agreement;
                                try {
                                    kf = KeyFactory.getInstance("DH");
                                } catch (NoSuchAlgorithmException e4) {
                                    kf = KeyFactory.getInstance("DiffieHellman");
                                }
                                try {
                                    agreement = KeyAgreement.getInstance("DH");
                                } catch (NoSuchAlgorithmException e5) {
                                    agreement = KeyAgreement.getInstance("DiffieHellman");
                                }
                                try {
                                    PublicKey clientPublic = kf.generatePublic(new DHPublicKeySpec(new BigInteger(1, this.clientKeyExchange.exchange_keys), this.serverKeyExchange.par1, this.serverKeyExchange.par2));
                                    agreement.init(this.privKey);
                                    agreement.doPhase(clientPublic, true);
                                    this.preMasterSecret = agreement.generateSecret();
                                } catch (Exception e32) {
                                    fatalAlert((byte) 80, "INTERNAL ERROR", e32);
                                    return;
                                }
                            }
                        }
                        computerMasterSecret();
                        break;
                    }
                    unexpectedMessage();
                    return;
                case 20:
                    if (this.isResuming || this.changeCipherSpecReceived) {
                        this.clientFinished = new Finished(this.io_stream, length);
                        verifyFinished(this.clientFinished.getData());
                        this.parameters.getServerSessionContext().putSession(this.session);
                        if (!this.isResuming) {
                            sendChangeCipherSpec();
                            break;
                        }
                        this.session.lastAccessedTime = System.currentTimeMillis();
                        this.status = 3;
                        break;
                    }
                    unexpectedMessage();
                    return;
                    break;
                default:
                    unexpectedMessage();
                    return;
            }
        }
    }

    public void unwrapSSLv2(byte[] bytes) {
        this.io_stream.append(bytes);
        this.io_stream.mark();
        try {
            this.clientHello = new ClientHello(this.io_stream);
            if (this.nonBlocking) {
                this.delegatedTasks.add(new DelegatedTask(new C00622(), this, AccessController.getContext()));
            } else {
                processClientHello();
            }
        } catch (IOException e) {
            this.io_stream.reset();
        }
    }

    void processClientHello() {
        CipherSuite cipher_suite;
        Exception e;
        DigitalSignature ds;
        KeyPair kp;
        DHPublicKey dhkey;
        KeyFactory kf;
        byte[] tmpLength;
        byte[] tmp;
        byte[] bArr;
        for (byte b : this.clientHello.compression_methods) {
            if (b == (byte) 0) {
                break;
            }
        }
        fatalAlert((byte) 40, "HANDSHAKE FAILURE. Incorrect client hello message");
        if (!ProtocolVersion.isSupported(this.clientHello.client_version)) {
            fatalAlert((byte) 70, "PROTOCOL VERSION. Unsupported client version " + this.clientHello.client_version[0] + this.clientHello.client_version[1]);
        }
        this.isResuming = false;
        if (this.clientHello.session_id.length != 0) {
            boolean reuseCurrent = false;
            if (this.session != null && Arrays.equals(this.session.id, this.clientHello.session_id)) {
                if (this.session.isValid()) {
                    this.isResuming = true;
                } else {
                    reuseCurrent = true;
                }
            }
            SSLSessionImpl sessionToResume = findSessionToResume(this.clientHello.session_id);
            if (sessionToResume == null || !sessionToResume.isValid()) {
                if (!this.parameters.getEnableSessionCreation()) {
                    if (reuseCurrent) {
                        sendWarningAlert((byte) 100);
                        this.status = 2;
                        clearMessages();
                        return;
                    }
                    fatalAlert((byte) 40, "SSL Session may not be created");
                }
                this.session = null;
            } else {
                this.session = (SSLSessionImpl) sessionToResume.clone();
                this.isResuming = true;
            }
        }
        if (this.isResuming) {
            cipher_suite = this.session.cipherSuite;
            for (Object equals : this.clientHello.cipher_suites) {
                if (cipher_suite.equals(equals)) {
                    break;
                }
            }
            fatalAlert((byte) 40, "HANDSHAKE FAILURE. Incorrect client hello message");
        } else {
            cipher_suite = selectSuite(this.clientHello.cipher_suites);
            if (cipher_suite == null) {
                fatalAlert((byte) 40, "HANDSHAKE FAILURE. NO COMMON SUITE");
            }
            if (!this.parameters.getEnableSessionCreation()) {
                fatalAlert((byte) 40, "SSL Session may not be created");
            }
            this.session = new SSLSessionImpl(cipher_suite, this.parameters.getSecureRandom());
        }
        this.recordProtocol.setVersion(this.clientHello.client_version);
        this.session.protocol = ProtocolVersion.getByVersion(this.clientHello.client_version);
        this.session.clientRandom = this.clientHello.random;
        this.serverHello = new ServerHello(this.parameters.getSecureRandom(), this.clientHello.client_version, this.session.getId(), cipher_suite, (byte) 0);
        this.session.serverRandom = this.serverHello.random;
        send(this.serverHello);
        if (this.isResuming) {
            sendChangeCipherSpec();
            return;
        }
        if (!cipher_suite.isAnonymous()) {
            String alias;
            X509Certificate[] certs = null;
            String certType = null;
            if (cipher_suite.keyExchange == CipherSuite.KeyExchange_RSA || cipher_suite.keyExchange == CipherSuite.KeyExchange_RSA_EXPORT || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_RSA || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_RSA_EXPORT) {
                certType = "RSA";
            } else if (cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_DSS || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_DSS_EXPORT) {
                certType = "DSA";
            } else if (cipher_suite.keyExchange == CipherSuite.KeyExchange_DH_DSS) {
                certType = "DH_DSA";
            } else if (cipher_suite.keyExchange == CipherSuite.KeyExchange_DH_RSA) {
                certType = "DH_RSA";
            }
            X509KeyManager km = this.parameters.getKeyManager();
            if (km instanceof X509ExtendedKeyManager) {
                X509ExtendedKeyManager ekm = (X509ExtendedKeyManager) km;
                if (this.socketOwner != null) {
                    alias = ekm.chooseServerAlias(certType, null, this.socketOwner);
                } else {
                    alias = ekm.chooseEngineServerAlias(certType, null, this.engineOwner);
                }
                if (alias != null) {
                    certs = ekm.getCertificateChain(alias);
                }
            } else {
                alias = km.chooseServerAlias(certType, null, this.socketOwner);
                if (alias != null) {
                    certs = km.getCertificateChain(alias);
                }
            }
            if (certs == null) {
                fatalAlert((byte) 40, "NO SERVER CERTIFICATE FOUND");
                return;
            }
            this.session.localCertificates = certs;
            this.serverCert = new CertificateMessage(certs);
            this.privKey = this.parameters.getKeyManager().getPrivateKey(alias);
            send(this.serverCert);
        }
        RSAPublicKey rsakey = null;
        DHPublicKeySpec dhkeySpec = null;
        byte[] hash = null;
        BigInteger p = null;
        BigInteger g = null;
        KeyPairGenerator kpg = null;
        try {
            if (cipher_suite.keyExchange == CipherSuite.KeyExchange_RSA_EXPORT) {
                if (HandshakeProtocol.getRSAKeyLength(this.serverCert.certs[0].getPublicKey()) > 512) {
                    kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(512);
                }
            } else if (cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_DSS || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_DSS_EXPORT || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_RSA || cipher_suite.keyExchange == CipherSuite.KeyExchange_DHE_RSA_EXPORT || cipher_suite.keyExchange == CipherSuite.KeyExchange_DH_anon || cipher_suite.keyExchange == CipherSuite.KeyExchange_DH_anon_EXPORT) {
                try {
                    kpg = KeyPairGenerator.getInstance("DH");
                } catch (NoSuchAlgorithmException e2) {
                    kpg = KeyPairGenerator.getInstance("DiffieHellman");
                }
                BigInteger bigInteger = new BigInteger(1, DHParameters.getPrime());
                try {
                    bigInteger = new BigInteger("2");
                } catch (Exception e3) {
                    e = e3;
                    p = bigInteger;
                    fatalAlert((byte) 80, "INTERNAL ERROR", e);
                    if (kpg != null) {
                        ds = new DigitalSignature(cipher_suite.keyExchange);
                        try {
                            kp = kpg.genKeyPair();
                            if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                                dhkey = (DHPublicKey) kp.getPublic();
                                try {
                                    kf = KeyFactory.getInstance("DH");
                                } catch (NoSuchAlgorithmException e4) {
                                    kf = KeyFactory.getInstance("DiffieHellman");
                                }
                                dhkeySpec = (DHPublicKeySpec) kf.getKeySpec(dhkey, DHPublicKeySpec.class);
                            } else {
                                rsakey = (RSAPublicKey) kp.getPublic();
                            }
                            if (cipher_suite.isAnonymous()) {
                                this.privKey = kp.getPrivate();
                            } else {
                                ds.init(this.privKey);
                                this.privKey = kp.getPrivate();
                                ds.update(this.clientHello.getRandom());
                                ds.update(this.serverHello.getRandom());
                                tmpLength = new byte[2];
                                if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                                    tmp = dhkeySpec.getP().toByteArray();
                                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                    tmpLength[1] = (byte) (tmp.length & 255);
                                    ds.update(tmp);
                                    tmp = dhkeySpec.getG().toByteArray();
                                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                    tmpLength[1] = (byte) (tmp.length & 255);
                                    ds.update(tmp);
                                    tmp = dhkeySpec.getY().toByteArray();
                                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                    tmpLength[1] = (byte) (tmp.length & 255);
                                    ds.update(tmp);
                                } else {
                                    tmp = rsakey.getModulus().toByteArray();
                                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                    tmpLength[1] = (byte) (tmp.length & 255);
                                    ds.update(tmpLength);
                                    ds.update(tmp);
                                    tmp = rsakey.getPublicExponent().toByteArray();
                                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                    tmpLength[1] = (byte) (tmp.length & 255);
                                    ds.update(tmp);
                                }
                                hash = ds.sign();
                            }
                        } catch (Exception e5) {
                            fatalAlert((byte) 80, "INTERNAL ERROR", e5);
                        }
                        if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                            this.serverKeyExchange = new ServerKeyExchange(p, g, dhkeySpec.getY(), hash);
                        } else {
                            this.serverKeyExchange = new ServerKeyExchange(rsakey.getModulus(), rsakey.getPublicExponent(), null, hash);
                        }
                        send(this.serverKeyExchange);
                    }
                    try {
                        bArr = new byte[2];
                        this.certificateRequest = new CertificateRequest(new byte[]{(byte) 1, (byte) 2}, this.parameters.getTrustManager().getAcceptedIssuers());
                        send(this.certificateRequest);
                    } catch (ClassCastException e6) {
                    }
                    this.serverHelloDone = new ServerHelloDone();
                    send(this.serverHelloDone);
                    this.status = 1;
                }
                try {
                    kpg.initialize(new DHParameterSpec(bigInteger, bigInteger));
                    g = bigInteger;
                    p = bigInteger;
                } catch (Exception e7) {
                    e5 = e7;
                    g = bigInteger;
                    p = bigInteger;
                    fatalAlert((byte) 80, "INTERNAL ERROR", e5);
                    if (kpg != null) {
                        ds = new DigitalSignature(cipher_suite.keyExchange);
                        kp = kpg.genKeyPair();
                        if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                            dhkey = (DHPublicKey) kp.getPublic();
                            kf = KeyFactory.getInstance("DH");
                            dhkeySpec = (DHPublicKeySpec) kf.getKeySpec(dhkey, DHPublicKeySpec.class);
                        } else {
                            rsakey = (RSAPublicKey) kp.getPublic();
                        }
                        if (cipher_suite.isAnonymous()) {
                            this.privKey = kp.getPrivate();
                        } else {
                            ds.init(this.privKey);
                            this.privKey = kp.getPrivate();
                            ds.update(this.clientHello.getRandom());
                            ds.update(this.serverHello.getRandom());
                            tmpLength = new byte[2];
                            if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                                tmp = dhkeySpec.getP().toByteArray();
                                tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                tmpLength[1] = (byte) (tmp.length & 255);
                                ds.update(tmp);
                                tmp = dhkeySpec.getG().toByteArray();
                                tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                tmpLength[1] = (byte) (tmp.length & 255);
                                ds.update(tmp);
                                tmp = dhkeySpec.getY().toByteArray();
                                tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                tmpLength[1] = (byte) (tmp.length & 255);
                                ds.update(tmp);
                            } else {
                                tmp = rsakey.getModulus().toByteArray();
                                tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                tmpLength[1] = (byte) (tmp.length & 255);
                                ds.update(tmpLength);
                                ds.update(tmp);
                                tmp = rsakey.getPublicExponent().toByteArray();
                                tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                                tmpLength[1] = (byte) (tmp.length & 255);
                                ds.update(tmp);
                            }
                            hash = ds.sign();
                        }
                        if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                            this.serverKeyExchange = new ServerKeyExchange(p, g, dhkeySpec.getY(), hash);
                        } else {
                            this.serverKeyExchange = new ServerKeyExchange(rsakey.getModulus(), rsakey.getPublicExponent(), null, hash);
                        }
                        send(this.serverKeyExchange);
                    }
                    bArr = new byte[2];
                    this.certificateRequest = new CertificateRequest(new byte[]{(byte) 1, (byte) 2}, this.parameters.getTrustManager().getAcceptedIssuers());
                    send(this.certificateRequest);
                    this.serverHelloDone = new ServerHelloDone();
                    send(this.serverHelloDone);
                    this.status = 1;
                }
            }
        } catch (Exception e8) {
            e5 = e8;
            fatalAlert((byte) 80, "INTERNAL ERROR", e5);
            if (kpg != null) {
                ds = new DigitalSignature(cipher_suite.keyExchange);
                kp = kpg.genKeyPair();
                if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                    rsakey = (RSAPublicKey) kp.getPublic();
                } else {
                    dhkey = (DHPublicKey) kp.getPublic();
                    kf = KeyFactory.getInstance("DH");
                    dhkeySpec = (DHPublicKeySpec) kf.getKeySpec(dhkey, DHPublicKeySpec.class);
                }
                if (cipher_suite.isAnonymous()) {
                    ds.init(this.privKey);
                    this.privKey = kp.getPrivate();
                    ds.update(this.clientHello.getRandom());
                    ds.update(this.serverHello.getRandom());
                    tmpLength = new byte[2];
                    if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                        tmp = rsakey.getModulus().toByteArray();
                        tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                        tmpLength[1] = (byte) (tmp.length & 255);
                        ds.update(tmpLength);
                        ds.update(tmp);
                        tmp = rsakey.getPublicExponent().toByteArray();
                        tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                        tmpLength[1] = (byte) (tmp.length & 255);
                        ds.update(tmp);
                    } else {
                        tmp = dhkeySpec.getP().toByteArray();
                        tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                        tmpLength[1] = (byte) (tmp.length & 255);
                        ds.update(tmp);
                        tmp = dhkeySpec.getG().toByteArray();
                        tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                        tmpLength[1] = (byte) (tmp.length & 255);
                        ds.update(tmp);
                        tmp = dhkeySpec.getY().toByteArray();
                        tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                        tmpLength[1] = (byte) (tmp.length & 255);
                        ds.update(tmp);
                    }
                    hash = ds.sign();
                } else {
                    this.privKey = kp.getPrivate();
                }
                if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                    this.serverKeyExchange = new ServerKeyExchange(rsakey.getModulus(), rsakey.getPublicExponent(), null, hash);
                } else {
                    this.serverKeyExchange = new ServerKeyExchange(p, g, dhkeySpec.getY(), hash);
                }
                send(this.serverKeyExchange);
            }
            bArr = new byte[2];
            this.certificateRequest = new CertificateRequest(new byte[]{(byte) 1, (byte) 2}, this.parameters.getTrustManager().getAcceptedIssuers());
            send(this.certificateRequest);
            this.serverHelloDone = new ServerHelloDone();
            send(this.serverHelloDone);
            this.status = 1;
        }
        if (kpg != null) {
            ds = new DigitalSignature(cipher_suite.keyExchange);
            kp = kpg.genKeyPair();
            if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                rsakey = (RSAPublicKey) kp.getPublic();
            } else {
                dhkey = (DHPublicKey) kp.getPublic();
                kf = KeyFactory.getInstance("DH");
                dhkeySpec = (DHPublicKeySpec) kf.getKeySpec(dhkey, DHPublicKeySpec.class);
            }
            if (cipher_suite.isAnonymous()) {
                ds.init(this.privKey);
                this.privKey = kp.getPrivate();
                ds.update(this.clientHello.getRandom());
                ds.update(this.serverHello.getRandom());
                tmpLength = new byte[2];
                if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                    tmp = rsakey.getModulus().toByteArray();
                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                    tmpLength[1] = (byte) (tmp.length & 255);
                    ds.update(tmpLength);
                    ds.update(tmp);
                    tmp = rsakey.getPublicExponent().toByteArray();
                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                    tmpLength[1] = (byte) (tmp.length & 255);
                    ds.update(tmp);
                } else {
                    tmp = dhkeySpec.getP().toByteArray();
                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                    tmpLength[1] = (byte) (tmp.length & 255);
                    ds.update(tmp);
                    tmp = dhkeySpec.getG().toByteArray();
                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                    tmpLength[1] = (byte) (tmp.length & 255);
                    ds.update(tmp);
                    tmp = dhkeySpec.getY().toByteArray();
                    tmpLength[0] = (byte) ((tmp.length & 65280) >>> 8);
                    tmpLength[1] = (byte) (tmp.length & 255);
                    ds.update(tmp);
                }
                hash = ds.sign();
            } else {
                this.privKey = kp.getPrivate();
            }
            if (cipher_suite.keyExchange != CipherSuite.KeyExchange_RSA_EXPORT) {
                this.serverKeyExchange = new ServerKeyExchange(rsakey.getModulus(), rsakey.getPublicExponent(), null, hash);
            } else {
                this.serverKeyExchange = new ServerKeyExchange(p, g, dhkeySpec.getY(), hash);
            }
            send(this.serverKeyExchange);
        }
        if (this.parameters.getWantClientAuth() || this.parameters.getNeedClientAuth()) {
            bArr = new byte[2];
            this.certificateRequest = new CertificateRequest(new byte[]{(byte) 1, (byte) 2}, this.parameters.getTrustManager().getAcceptedIssuers());
            send(this.certificateRequest);
        }
        this.serverHelloDone = new ServerHelloDone();
        send(this.serverHelloDone);
        this.status = 1;
    }

    protected void makeFinished() {
        byte[] verify_data;
        boolean isTLS = this.serverHello.server_version[1] == (byte) 1;
        if (isTLS) {
            verify_data = new byte[12];
            computerVerifyDataTLS(ExporterLabel.server_finished, verify_data);
        } else {
            verify_data = new byte[36];
            computerVerifyDataSSLv3(SSLv3Constants.server, verify_data);
        }
        this.serverFinished = new Finished(verify_data);
        send(this.serverFinished);
        if (this.isResuming) {
            if (isTLS) {
                computerReferenceVerifyDataTLS(ExporterLabel.client_finished);
            } else {
                computerReferenceVerifyDataSSLv3(SSLv3Constants.client);
            }
            this.status = 1;
            return;
        }
        this.session.lastAccessedTime = System.currentTimeMillis();
        this.status = 3;
    }

    private SSLSessionImpl findSessionToResume(byte[] session_id) {
        return (SSLSessionImpl) this.parameters.getServerSessionContext().getSession(session_id);
    }

    private CipherSuite selectSuite(CipherSuite[] client_suites) {
        for (int i = 0; i < client_suites.length; i++) {
            if (client_suites[i].supported) {
                for (Object equals : this.parameters.enabledCipherSuites) {
                    if (client_suites[i].equals(equals)) {
                        return client_suites[i];
                    }
                }
                continue;
            }
        }
        return null;
    }

    public void receiveChangeCipherSpec() {
        if (!this.isResuming) {
            if ((this.parameters.getNeedClientAuth() && this.clientCert == null) || this.clientKeyExchange == null || (this.clientCert != null && !this.clientKeyExchange.isEmpty() && this.certificateVerify == null)) {
                unexpectedMessage();
            } else {
                this.changeCipherSpecReceived = true;
            }
            if (this.serverHello.server_version[1] == (byte) 1) {
                computerReferenceVerifyDataTLS(ExporterLabel.client_finished);
            } else {
                computerReferenceVerifyDataSSLv3(SSLv3Constants.client);
            }
        } else if (this.serverFinished == null) {
            unexpectedMessage();
        } else {
            this.changeCipherSpecReceived = true;
        }
    }
}
