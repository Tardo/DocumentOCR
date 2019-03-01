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
import org.bouncycastle.util.Integers;

public abstract class TlsProtocol {
    protected static final short CS_CERTIFICATE_REQUEST = (short) 6;
    protected static final short CS_CERTIFICATE_VERIFY = (short) 11;
    protected static final short CS_CLIENT_CERTIFICATE = (short) 9;
    protected static final short CS_CLIENT_CHANGE_CIPHER_SPEC = (short) 12;
    protected static final short CS_CLIENT_FINISHED = (short) 13;
    protected static final short CS_CLIENT_HELLO = (short) 1;
    protected static final short CS_CLIENT_KEY_EXCHANGE = (short) 10;
    protected static final short CS_CLIENT_SUPPLEMENTAL_DATA = (short) 8;
    protected static final short CS_SERVER_CERTIFICATE = (short) 4;
    protected static final short CS_SERVER_CHANGE_CIPHER_SPEC = (short) 15;
    protected static final short CS_SERVER_FINISHED = (short) 16;
    protected static final short CS_SERVER_HELLO = (short) 2;
    protected static final short CS_SERVER_HELLO_DONE = (short) 7;
    protected static final short CS_SERVER_KEY_EXCHANGE = (short) 5;
    protected static final short CS_SERVER_SESSION_TICKET = (short) 14;
    protected static final short CS_SERVER_SUPPLEMENTAL_DATA = (short) 3;
    protected static final short CS_START = (short) 0;
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(65281);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(35);
    private static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";
    private ByteQueue alertQueue = new ByteQueue();
    private volatile boolean appDataReady = false;
    private ByteQueue applicationDataQueue = new ByteQueue();
    private ByteQueue changeCipherSpecQueue = new ByteQueue();
    private volatile boolean closed = false;
    protected short connection_state = (short) 0;
    protected boolean expectSessionTicket = false;
    private byte[] expected_verify_data = null;
    private volatile boolean failedWithError = false;
    private ByteQueue handshakeQueue = new ByteQueue();
    protected RecordStream recordStream;
    protected SecureRandom secureRandom;
    protected boolean secure_renegotiation = false;
    protected SecurityParameters securityParameters = null;
    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;
    private volatile boolean writeExtraEmptyRecords = true;

    public TlsProtocol(InputStream inputStream, OutputStream outputStream, SecureRandom secureRandom) {
        this.recordStream = new RecordStream(this, inputStream, outputStream);
        this.secureRandom = secureRandom;
    }

    protected static boolean arrayContains(int[] iArr, int i) {
        for (int i2 : iArr) {
            if (i2 == i) {
                return true;
            }
        }
        return false;
    }

    protected static boolean arrayContains(short[] sArr, short s) {
        for (short s2 : sArr) {
            if (s2 == s) {
                return true;
            }
        }
        return false;
    }

    protected static void assertEmpty(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (byteArrayInputStream.available() > 0) {
            throw new TlsFatalAlert((short) 50);
        }
    }

    protected static byte[] createRandomBlock(SecureRandom secureRandom) {
        byte[] bArr = new byte[32];
        secureRandom.nextBytes(bArr);
        TlsUtils.writeGMTUnixTime(bArr, 0);
        return bArr;
    }

    protected static byte[] createRenegotiationInfo(byte[] bArr) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeOpaque8(bArr, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected static void establishMasterSecret(TlsContext tlsContext, TlsKeyExchange tlsKeyExchange) throws IOException {
        byte[] generatePremasterSecret = tlsKeyExchange.generatePremasterSecret();
        try {
            tlsContext.getSecurityParameters().masterSecret = TlsUtils.calculateMasterSecret(tlsContext, generatePremasterSecret);
        } finally {
            if (generatePremasterSecret != null) {
                Arrays.fill(generatePremasterSecret, (byte) 0);
            }
        }
    }

    protected static int getPRFAlgorithm(int i) {
        switch (i) {
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
            case 60:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /*62*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256 /*63*/:
            case 64:
            case 103:
            case 104:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 /*105*/:
            case 106:
            case 107:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /*156*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /*158*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /*160*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 /*162*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 /*164*/:
            case 49187:
            case 49189:
            case 49191:
            case 49193:
            case 49195:
            case 49197:
            case 49199:
            case 49201:
                return 1;
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /*157*/:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /*159*/:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 /*161*/:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 /*163*/:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 /*165*/:
            case 49188:
            case 49190:
            case 49192:
            case 49194:
            case 49196:
            case 49198:
            case 49200:
            case 49202:
                return 2;
            default:
                return 0;
        }
    }

    private void processAlert() throws IOException {
        while (this.alertQueue.size() >= 2) {
            byte[] bArr = new byte[2];
            this.alertQueue.read(bArr, 0, 2, 0);
            this.alertQueue.removeData(2);
            short s = (short) bArr[0];
            short s2 = (short) bArr[1];
            getPeer().notifyAlertReceived(s, s2);
            if (s == (short) 2) {
                this.failedWithError = true;
                this.closed = true;
                try {
                    this.recordStream.close();
                } catch (Exception e) {
                }
                throw new IOException(TLS_ERROR_MESSAGE);
            }
            if (s2 == (short) 0) {
                handleClose(false);
            }
            handleWarningMessage(s2);
        }
    }

    private void processApplicationData() {
    }

    private void processChangeCipherSpec() throws IOException {
        while (this.changeCipherSpecQueue.size() > 0) {
            byte[] bArr = new byte[1];
            this.changeCipherSpecQueue.read(bArr, 0, 1, 0);
            this.changeCipherSpecQueue.removeData(1);
            if (bArr[0] != (byte) 1) {
                failWithError((short) 2, (short) 10);
            }
            this.recordStream.receivedReadCipherSpec();
            handleChangeCipherSpecMessage();
        }
    }

    private void processHandshake() throws IOException {
        int i;
        do {
            if (this.handshakeQueue.size() >= 4) {
                byte[] bArr = new byte[4];
                this.handshakeQueue.read(bArr, 0, 4, 0);
                InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
                int readUint24 = TlsUtils.readUint24(byteArrayInputStream);
                if (this.handshakeQueue.size() >= readUint24 + 4) {
                    byte[] bArr2 = new byte[readUint24];
                    this.handshakeQueue.read(bArr2, 0, readUint24, 4);
                    this.handshakeQueue.removeData(readUint24 + 4);
                    switch (readUint8) {
                        case (short) 0:
                            break;
                        case (short) 20:
                            if (this.expected_verify_data == null) {
                                this.expected_verify_data = createVerifyData(!getContext().isServer());
                                break;
                            }
                            break;
                    }
                    this.recordStream.updateHandshakeData(bArr, 0, 4);
                    this.recordStream.updateHandshakeData(bArr2, 0, readUint24);
                    handleHandshakeMessage(readUint8, bArr2);
                    i = 1;
                    continue;
                }
            }
            i = 0;
            continue;
        } while (i != 0);
    }

    protected static Hashtable readExtensions(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (byteArrayInputStream.available() < 1) {
            return null;
        }
        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        InputStream byteArrayInputStream2 = new ByteArrayInputStream(readOpaque16);
        Hashtable hashtable = new Hashtable();
        while (byteArrayInputStream2.available() > 0) {
            if (hashtable.put(Integers.valueOf(TlsUtils.readUint16(byteArrayInputStream2)), TlsUtils.readOpaque16(byteArrayInputStream2)) != null) {
                throw new TlsFatalAlert((short) 47);
            }
        }
        return hashtable;
    }

    protected static Vector readSupplementalDataMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        byte[] readOpaque24 = TlsUtils.readOpaque24(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        InputStream byteArrayInputStream2 = new ByteArrayInputStream(readOpaque24);
        Vector vector = new Vector();
        while (byteArrayInputStream2.available() > 0) {
            vector.addElement(new SupplementalDataEntry(TlsUtils.readUint16(byteArrayInputStream2), TlsUtils.readOpaque16(byteArrayInputStream2)));
        }
        return vector;
    }

    protected static void writeExtensions(OutputStream outputStream, Hashtable hashtable) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Enumeration keys = hashtable.keys();
        while (keys.hasMoreElements()) {
            Integer num = (Integer) keys.nextElement();
            byte[] bArr = (byte[]) hashtable.get(num);
            TlsUtils.writeUint16(num.intValue(), byteArrayOutputStream);
            TlsUtils.writeOpaque16(bArr, byteArrayOutputStream);
        }
        TlsUtils.writeOpaque16(byteArrayOutputStream.toByteArray(), outputStream);
    }

    protected static void writeSupplementalData(OutputStream outputStream, Vector vector) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = 0; i < vector.size(); i++) {
            SupplementalDataEntry supplementalDataEntry = (SupplementalDataEntry) vector.elementAt(i);
            TlsUtils.writeUint16(supplementalDataEntry.getDataType(), byteArrayOutputStream);
            TlsUtils.writeOpaque16(supplementalDataEntry.getData(), byteArrayOutputStream);
        }
        TlsUtils.writeOpaque24(byteArrayOutputStream.toByteArray(), outputStream);
    }

    public void close() throws IOException {
        handleClose(true);
    }

    protected void completeHandshake() throws IOException {
        this.expected_verify_data = null;
        while (this.connection_state != (short) 16) {
            safeReadRecord();
        }
        this.recordStream.finaliseHandshake();
        this.writeExtraEmptyRecords = getContext().getServerVersion().isEqualOrEarlierVersionOf(ProtocolVersion.TLSv10);
        if (!this.appDataReady) {
            this.appDataReady = true;
            this.tlsInputStream = new TlsInputStream(this);
            this.tlsOutputStream = new TlsOutputStream(this);
        }
    }

    protected byte[] createVerifyData(boolean z) {
        TlsContext context = getContext();
        return z ? TlsUtils.calculateVerifyData(context, ExporterLabel.server_finished, this.recordStream.getCurrentHash(TlsUtils.SSL_SERVER)) : TlsUtils.calculateVerifyData(context, ExporterLabel.client_finished, this.recordStream.getCurrentHash(TlsUtils.SSL_CLIENT));
    }

    protected void failWithError(short s, short s2) throws IOException {
        if (this.closed) {
            throw new IOException(TLS_ERROR_MESSAGE);
        }
        this.closed = true;
        if (s == (short) 2) {
            this.failedWithError = true;
        }
        raiseAlert(s, s2, null, null);
        this.recordStream.close();
        if (s == (short) 2) {
            throw new IOException(TLS_ERROR_MESSAGE);
        }
    }

    protected void flush() throws IOException {
        this.recordStream.flush();
    }

    protected abstract AbstractTlsContext getContext();

    public InputStream getInputStream() {
        return this.tlsInputStream;
    }

    public OutputStream getOutputStream() {
        return this.tlsOutputStream;
    }

    protected abstract TlsPeer getPeer();

    protected abstract void handleChangeCipherSpecMessage() throws IOException;

    protected void handleClose(boolean z) throws IOException {
        if (!this.closed) {
            if (z && !this.appDataReady) {
                raiseWarning((short) 90, "User canceled handshake");
            }
            failWithError((short) 1, (short) 0);
        }
    }

    protected abstract void handleHandshakeMessage(short s, byte[] bArr) throws IOException;

    protected void handleWarningMessage(short s) throws IOException {
    }

    protected void processFinishedMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        byte[] readFully = TlsUtils.readFully(this.expected_verify_data.length, (InputStream) byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        if (!Arrays.constantTimeAreEqual(this.expected_verify_data, readFully)) {
            failWithError((short) 2, (short) 51);
        }
    }

    protected void processRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        switch (s) {
            case (short) 20:
                this.changeCipherSpecQueue.addData(bArr, i, i2);
                processChangeCipherSpec();
                return;
            case (short) 21:
                this.alertQueue.addData(bArr, i, i2);
                processAlert();
                return;
            case (short) 22:
                this.handshakeQueue.addData(bArr, i, i2);
                processHandshake();
                return;
            case (short) 23:
                if (!this.appDataReady) {
                    failWithError((short) 2, (short) 10);
                }
                this.applicationDataQueue.addData(bArr, i, i2);
                processApplicationData();
                return;
            default:
                return;
        }
    }

    protected void raiseAlert(short s, short s2, String str, Exception exception) throws IOException {
        getPeer().notifyAlertRaised(s, s2, str, exception);
        safeWriteRecord((short) 21, new byte[]{(byte) s, (byte) s2}, 0, 2);
    }

    protected void raiseWarning(short s, String str) throws IOException {
        raiseAlert((short) 1, s, str, null);
    }

    protected int readApplicationData(byte[] bArr, int i, int i2) throws IOException {
        if (i2 < 1) {
            return 0;
        }
        while (this.applicationDataQueue.size() == 0) {
            if (!this.closed) {
                safeReadRecord();
            } else if (!this.failedWithError) {
                return -1;
            } else {
                throw new IOException(TLS_ERROR_MESSAGE);
            }
        }
        int min = Math.min(i2, this.applicationDataQueue.size());
        this.applicationDataQueue.read(bArr, i, min, 0);
        this.applicationDataQueue.removeData(min);
        return min;
    }

    protected void safeReadRecord() throws IOException {
        try {
            this.recordStream.readRecord();
        } catch (TlsFatalAlert e) {
            if (!this.closed) {
                failWithError((short) 2, e.getAlertDescription());
            }
            throw e;
        } catch (IOException e2) {
            if (!this.closed) {
                failWithError((short) 2, (short) 80);
            }
            throw e2;
        } catch (RuntimeException e3) {
            if (!this.closed) {
                failWithError((short) 2, (short) 80);
            }
            throw e3;
        }
    }

    protected void safeWriteRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        try {
            this.recordStream.writeRecord(s, bArr, i, i2);
        } catch (TlsFatalAlert e) {
            if (!this.closed) {
                failWithError((short) 2, e.getAlertDescription());
            }
            throw e;
        } catch (IOException e2) {
            if (!this.closed) {
                failWithError((short) 2, (short) 80);
            }
            throw e2;
        } catch (RuntimeException e3) {
            if (!this.closed) {
                failWithError((short) 2, (short) 80);
            }
            throw e3;
        }
    }

    protected void sendCertificateMessage(Certificate certificate) throws IOException {
        if (certificate == null) {
            certificate = Certificate.EMPTY_CHAIN;
        }
        if (certificate.getLength() == 0 && !getContext().isServer()) {
            ProtocolVersion serverVersion = getContext().getServerVersion();
            if (serverVersion.isSSL()) {
                raiseWarning((short) 41, serverVersion.toString() + " client didn't provide credentials");
                return;
            }
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 11, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        certificate.encode(byteArrayOutputStream);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void sendChangeCipherSpecMessage() throws IOException {
        byte[] bArr = new byte[]{(byte) 1};
        safeWriteRecord((short) 20, bArr, 0, bArr.length);
        this.recordStream.sentWriteCipherSpec();
    }

    protected void sendFinishedMessage() throws IOException {
        byte[] createVerifyData = createVerifyData(getContext().isServer());
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 20, byteArrayOutputStream);
        TlsUtils.writeUint24(createVerifyData.length, byteArrayOutputStream);
        byteArrayOutputStream.write(createVerifyData);
        createVerifyData = byteArrayOutputStream.toByteArray();
        safeWriteRecord((short) 22, createVerifyData, 0, createVerifyData.length);
    }

    protected void sendSupplementalDataMessage(Vector vector) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) 23, byteArrayOutputStream);
        TlsUtils.writeUint24(0, byteArrayOutputStream);
        writeSupplementalData(byteArrayOutputStream, vector);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint24(toByteArray.length - 4, toByteArray, 1);
        safeWriteRecord((short) 22, toByteArray, 0, toByteArray.length);
    }

    protected void writeData(byte[] bArr, int i, int i2) throws IOException {
        if (!this.closed) {
            while (i2 > 0) {
                if (this.writeExtraEmptyRecords) {
                    safeWriteRecord((short) 23, TlsUtils.EMPTY_BYTES, 0, 0);
                }
                int min = Math.min(i2, 16384);
                safeWriteRecord((short) 23, bArr, i, min);
                i += min;
                i2 -= min;
            }
        } else if (this.failedWithError) {
            throw new IOException(TLS_ERROR_MESSAGE);
        } else {
            throw new IOException("Sorry, connection has been closed, you cannot write more data");
        }
    }
}
