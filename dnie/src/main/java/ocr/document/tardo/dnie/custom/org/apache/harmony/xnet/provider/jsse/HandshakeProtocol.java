package custom.org.apache.harmony.xnet.provider.jsse;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Vector;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

public abstract class HandshakeProtocol {
    public static final int FINISHED = 3;
    public static final int NEED_TASK = 4;
    public static final int NEED_UNWRAP = 1;
    public static final int NOT_HANDSHAKING = 2;
    protected CertificateRequest certificateRequest;
    protected CertificateVerify certificateVerify;
    protected boolean changeCipherSpecReceived = false;
    protected CertificateMessage clientCert;
    protected Finished clientFinished;
    protected ClientHello clientHello;
    protected ClientKeyExchange clientKeyExchange;
    protected Exception delegatedTaskErr;
    protected Vector<DelegatedTask> delegatedTasks = new Vector();
    public SSLEngineImpl engineOwner;
    protected HandshakeIODataStream io_stream = new HandshakeIODataStream();
    protected boolean isResuming = false;
    private byte[] master_secret_bytes = new byte[]{(byte) 109, (byte) 97, (byte) 115, (byte) 116, (byte) 101, (byte) 114, (byte) 32, (byte) 115, (byte) 101, (byte) 99, (byte) 114, (byte) 101, (byte) 116};
    private boolean needSendCCSpec = false;
    protected boolean needSendHelloRequest = false;
    protected boolean nonBlocking;
    protected SSLParameters parameters;
    protected byte[] preMasterSecret;
    protected SSLRecordProtocol recordProtocol;
    protected CertificateMessage serverCert;
    protected Finished serverFinished;
    protected ServerHello serverHello;
    protected ServerHelloDone serverHelloDone;
    protected ServerKeyExchange serverKeyExchange;
    protected SSLSessionImpl session;
    public SSLSocketImpl socketOwner;
    protected int status = 2;
    private byte[] verify_data = new byte[12];

    abstract void makeFinished();

    abstract void receiveChangeCipherSpec();

    public abstract void start();

    public abstract void unwrap(byte[] bArr);

    public abstract void unwrapSSLv2(byte[] bArr);

    protected HandshakeProtocol(Object owner) {
        if (owner instanceof SSLEngineImpl) {
            this.engineOwner = (SSLEngineImpl) owner;
            this.nonBlocking = true;
            this.parameters = this.engineOwner.sslParameters;
        } else if (owner instanceof SSLSocketImpl) {
            this.socketOwner = (SSLSocketImpl) owner;
            this.nonBlocking = false;
            this.parameters = this.socketOwner.sslParameters;
        }
    }

    public void setRecordProtocol(SSLRecordProtocol recordProtocol) {
        this.recordProtocol = recordProtocol;
    }

    protected void stop() {
        clearMessages();
        this.status = 2;
    }

    public HandshakeStatus getStatus() {
        if (this.io_stream.hasData() || this.needSendCCSpec || this.needSendHelloRequest || this.delegatedTaskErr != null) {
            return HandshakeStatus.NEED_WRAP;
        }
        if (!this.delegatedTasks.isEmpty()) {
            return HandshakeStatus.NEED_TASK;
        }
        switch (this.status) {
            case 1:
                return HandshakeStatus.NEED_UNWRAP;
            case 3:
                this.status = 2;
                clearMessages();
                return HandshakeStatus.FINISHED;
            default:
                return HandshakeStatus.NOT_HANDSHAKING;
        }
    }

    public SSLSessionImpl getSession() {
        return this.session;
    }

    protected void sendChangeCipherSpec() {
        this.needSendCCSpec = true;
    }

    protected void sendHelloRequest() {
        this.needSendHelloRequest = true;
    }

    public byte[] wrap() {
        if (this.delegatedTaskErr != null) {
            Exception e = this.delegatedTaskErr;
            this.delegatedTaskErr = null;
            fatalAlert((byte) 40, "Error occured in delegated task:" + e.getMessage(), e);
        }
        if (this.io_stream.hasData()) {
            return this.recordProtocol.wrap((byte) 22, this.io_stream);
        }
        if (this.needSendCCSpec) {
            makeFinished();
            this.needSendCCSpec = false;
            return this.recordProtocol.getChangeCipherSpecMesage(getSession());
        } else if (!this.needSendHelloRequest) {
            return null;
        } else {
            this.needSendHelloRequest = false;
            return this.recordProtocol.wrap((byte) 22, new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0}, 0, 4);
        }
    }

    protected void sendWarningAlert(byte description) {
        this.recordProtocol.alert((byte) 1, description);
    }

    protected void fatalAlert(byte description, String reason) {
        throw new AlertException(description, new SSLHandshakeException(reason));
    }

    protected void fatalAlert(byte description, String reason, Exception cause) {
        throw new AlertException(description, new SSLException(reason, cause));
    }

    protected void fatalAlert(byte description, SSLException cause) {
        throw new AlertException(description, cause);
    }

    protected void computerReferenceVerifyDataTLS(String label) {
        computerVerifyDataTLS(label, this.verify_data);
    }

    protected void computerVerifyDataTLS(String label, byte[] buf) {
        byte[] md5_digest = this.io_stream.getDigestMD5();
        byte[] sha_digest = this.io_stream.getDigestSHA();
        byte[] digest = new byte[(md5_digest.length + sha_digest.length)];
        System.arraycopy(md5_digest, 0, digest, 0, md5_digest.length);
        System.arraycopy(sha_digest, 0, digest, md5_digest.length, sha_digest.length);
        try {
            PRF.computePRF(buf, this.session.master_secret, label.getBytes(), digest);
        } catch (GeneralSecurityException e) {
            fatalAlert((byte) 80, "PRF error", e);
        }
    }

    protected void computerReferenceVerifyDataSSLv3(byte[] sender) {
        this.verify_data = new byte[36];
        computerVerifyDataSSLv3(sender, this.verify_data);
    }

    protected void computerVerifyDataSSLv3(byte[] sender, byte[] buf) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            try {
                byte[] hanshake_messages = this.io_stream.getMessages();
                md5.update(hanshake_messages);
                md5.update(sender);
                md5.update(this.session.master_secret);
                byte[] b = md5.digest(SSLv3Constants.MD5pad1);
                md5.update(this.session.master_secret);
                md5.update(SSLv3Constants.MD5pad2);
                System.arraycopy(md5.digest(b), 0, buf, 0, 16);
                sha.update(hanshake_messages);
                sha.update(sender);
                sha.update(this.session.master_secret);
                b = sha.digest(SSLv3Constants.SHApad1);
                sha.update(this.session.master_secret);
                sha.update(SSLv3Constants.SHApad2);
                System.arraycopy(sha.digest(b), 0, buf, 16, 20);
            } catch (Exception e) {
                fatalAlert((byte) 80, "INTERNAL ERROR", e);
            }
        } catch (Exception e2) {
            fatalAlert((byte) 80, "Could not initialize the Digest Algorithms.", e2);
        }
    }

    protected void verifyFinished(byte[] data) {
        if (!Arrays.equals(this.verify_data, data)) {
            fatalAlert((byte) 40, "Incorrect FINISED");
        }
    }

    protected void unexpectedMessage() {
        fatalAlert((byte) 10, "UNEXPECTED MESSAGE");
    }

    public void send(Message message) {
        this.io_stream.writeUint8((long) message.getType());
        this.io_stream.writeUint24((long) message.length());
        message.send(this.io_stream);
    }

    public void computerMasterSecret() {
        byte[] seed = new byte[64];
        System.arraycopy(this.clientHello.getRandom(), 0, seed, 0, 32);
        System.arraycopy(this.serverHello.getRandom(), 0, seed, 32, 32);
        this.session.master_secret = new byte[48];
        if (this.serverHello.server_version[1] == (byte) 1) {
            try {
                PRF.computePRF(this.session.master_secret, this.preMasterSecret, this.master_secret_bytes, seed);
            } catch (GeneralSecurityException e) {
                fatalAlert((byte) 80, "PRF error", e);
            }
        } else {
            PRF.computePRF_SSLv3(this.session.master_secret, this.preMasterSecret, seed);
        }
        Arrays.fill(this.preMasterSecret, (byte) 0);
        this.preMasterSecret = null;
    }

    public Runnable getTask() {
        if (this.delegatedTasks.isEmpty()) {
            return null;
        }
        return (Runnable) this.delegatedTasks.remove(0);
    }

    protected void clearMessages() {
        this.io_stream.clearBuffer();
        this.clientHello = null;
        this.serverHello = null;
        this.serverCert = null;
        this.serverKeyExchange = null;
        this.certificateRequest = null;
        this.serverHelloDone = null;
        this.clientCert = null;
        this.clientKeyExchange = null;
        this.certificateVerify = null;
        this.clientFinished = null;
        this.serverFinished = null;
    }

    protected static int getRSAKeyLength(PublicKey pk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger mod;
        if (pk instanceof RSAKey) {
            mod = ((RSAKey) pk).getModulus();
        } else {
            mod = ((RSAPublicKeySpec) KeyFactory.getInstance("RSA").getKeySpec(pk, RSAPublicKeySpec.class)).getModulus();
        }
        return mod.bitLength();
    }

    protected void shutdown() {
        clearMessages();
        this.session = null;
        this.preMasterSecret = null;
        this.delegatedTasks.clear();
    }
}
