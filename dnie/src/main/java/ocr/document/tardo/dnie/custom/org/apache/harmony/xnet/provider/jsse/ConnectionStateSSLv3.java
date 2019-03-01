package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLProtocolException;

public class ConnectionStateSSLv3 extends ConnectionState {
    private final byte[] mac_material_part = new byte[3];
    private final byte[] mac_read_secret;
    private final byte[] mac_write_secret;
    private final MessageDigest messageDigest;
    private final byte[] pad_1;
    private final byte[] pad_2;

    protected ConnectionStateSSLv3(SSLSessionImpl session) {
        try {
            CipherSuite cipherSuite = session.cipherSuite;
            boolean is_exportabe = cipherSuite.isExportable();
            this.hash_size = cipherSuite.getMACLength();
            int key_size = is_exportabe ? cipherSuite.keyMaterial : cipherSuite.expandedKeyMaterial;
            int iv_size = cipherSuite.getBlockSize();
            String algName = cipherSuite.getBulkEncryptionAlgorithm();
            String hashName = cipherSuite.getHashName();
            if (this.logger != null) {
                this.logger.println("ConnectionStateSSLv3.create:");
                this.logger.println("  cipher suite name: " + session.getCipherSuite());
                this.logger.println("  encryption alg name: " + algName);
                this.logger.println("  hash alg name: " + hashName);
                this.logger.println("  hash size: " + this.hash_size);
                this.logger.println("  block size: " + iv_size);
                this.logger.println("  IV size (== block size):" + iv_size);
                this.logger.println("  key size: " + key_size);
            }
            byte[] clientRandom = session.clientRandom;
            Object serverRandom = session.serverRandom;
            Object key_block = new byte[(((this.hash_size * 2) + (key_size * 2)) + (iv_size * 2))];
            Object seed = new byte[(clientRandom.length + serverRandom.length)];
            System.arraycopy(serverRandom, 0, seed, 0, serverRandom.length);
            System.arraycopy(clientRandom, 0, seed, serverRandom.length, clientRandom.length);
            PRF.computePRF_SSLv3(key_block, session.master_secret, seed);
            byte[] client_mac_secret = new byte[this.hash_size];
            Object server_mac_secret = new byte[this.hash_size];
            byte[] client_key = new byte[key_size];
            byte[] server_key = new byte[key_size];
            boolean is_client = !session.isServer;
            this.is_block_cipher = iv_size > 0;
            System.arraycopy(key_block, 0, client_mac_secret, 0, this.hash_size);
            System.arraycopy(key_block, this.hash_size, server_mac_secret, 0, this.hash_size);
            System.arraycopy(key_block, this.hash_size * 2, client_key, 0, key_size);
            System.arraycopy(key_block, (this.hash_size * 2) + key_size, server_key, 0, key_size);
            IvParameterSpec clientIV = null;
            IvParameterSpec serverIV = null;
            IvParameterSpec ivParameterSpec;
            if (is_exportabe) {
                if (this.logger != null) {
                    this.logger.println("ConnectionStateSSLv3: is_exportable");
                }
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                md5.update(client_key);
                md5.update(clientRandom);
                md5.update(serverRandom);
                client_key = md5.digest();
                md5.update(server_key);
                md5.update(serverRandom);
                md5.update(clientRandom);
                server_key = md5.digest();
                key_size = cipherSuite.expandedKeyMaterial;
                if (this.is_block_cipher) {
                    md5.update(clientRandom);
                    md5.update(serverRandom);
                    clientIV = new IvParameterSpec(md5.digest(), 0, iv_size);
                    md5.update(serverRandom);
                    md5.update(clientRandom);
                    ivParameterSpec = new IvParameterSpec(md5.digest(), 0, iv_size);
                }
            } else if (this.is_block_cipher) {
                clientIV = new IvParameterSpec(key_block, (this.hash_size * 2) + (key_size * 2), iv_size);
                ivParameterSpec = new IvParameterSpec(key_block, ((this.hash_size * 2) + (key_size * 2)) + iv_size, iv_size);
            }
            if (this.logger != null) {
                this.logger.println("is exportable: " + is_exportabe);
                this.logger.println("master_secret");
                this.logger.print(session.master_secret);
                this.logger.println("client_random");
                this.logger.print(clientRandom);
                this.logger.println("server_random");
                this.logger.print((byte[]) serverRandom);
                this.logger.println("client_mac_secret");
                this.logger.print(client_mac_secret);
                this.logger.println("server_mac_secret");
                this.logger.print((byte[]) server_mac_secret);
                this.logger.println("client_key");
                this.logger.print(client_key, 0, key_size);
                this.logger.println("server_key");
                this.logger.print(server_key, 0, key_size);
                if (clientIV != null) {
                    this.logger.println("client_iv");
                    this.logger.print(clientIV.getIV());
                    this.logger.println("server_iv");
                    this.logger.print(serverIV.getIV());
                } else {
                    this.logger.println("no IV.");
                }
            }
            this.encCipher = Cipher.getInstance(algName);
            this.decCipher = Cipher.getInstance(algName);
            this.messageDigest = MessageDigest.getInstance(hashName);
            if (is_client) {
                this.encCipher.init(1, new SecretKeySpec(client_key, 0, key_size, algName), clientIV);
                this.decCipher.init(2, new SecretKeySpec(server_key, 0, key_size, algName), serverIV);
                this.mac_write_secret = client_mac_secret;
                this.mac_read_secret = server_mac_secret;
            } else {
                this.encCipher.init(1, new SecretKeySpec(server_key, 0, key_size, algName), serverIV);
                this.decCipher.init(2, new SecretKeySpec(client_key, 0, key_size, algName), clientIV);
                this.mac_write_secret = server_mac_secret;
                this.mac_read_secret = client_mac_secret;
            }
            if (hashName.equals("MD5")) {
                this.pad_1 = SSLv3Constants.MD5pad1;
                this.pad_2 = SSLv3Constants.MD5pad2;
                return;
            }
            this.pad_1 = SSLv3Constants.SHApad1;
            this.pad_2 = SSLv3Constants.SHApad2;
        } catch (Exception e) {
            e.printStackTrace();
            throw new AlertException((byte) 80, new SSLProtocolException("Error during computation of security parameters"));
        }
    }

    protected byte[] encrypt(byte type, byte[] fragment, int offset, int len) {
        int padding_length = 0;
        try {
            int content_mac_length = len + this.hash_size;
            if (this.is_block_cipher) {
                content_mac_length++;
                padding_length = (8 - (content_mac_length & 7)) & 7;
            }
            byte[] res = new byte[(content_mac_length + padding_length)];
            System.arraycopy(fragment, offset, res, 0, len);
            this.mac_material_part[0] = type;
            this.mac_material_part[1] = (byte) ((65280 & len) >> 8);
            this.mac_material_part[2] = (byte) (len & 255);
            this.messageDigest.update(this.mac_write_secret);
            this.messageDigest.update(this.pad_1);
            this.messageDigest.update(this.write_seq_num);
            this.messageDigest.update(this.mac_material_part);
            this.messageDigest.update(fragment, offset, len);
            byte[] digest = this.messageDigest.digest();
            this.messageDigest.update(this.mac_write_secret);
            this.messageDigest.update(this.pad_2);
            this.messageDigest.update(digest);
            System.arraycopy(this.messageDigest.digest(), 0, res, len, this.hash_size);
            if (this.is_block_cipher) {
                Arrays.fill(res, content_mac_length - 1, res.length, (byte) padding_length);
            }
            if (this.logger != null) {
                this.logger.println("SSLRecordProtocol.encrypt: " + (this.is_block_cipher ? "GenericBlockCipher with padding[" + padding_length + "]:" : "GenericStreamCipher:"));
                this.logger.print(res);
            }
            byte[] rez = new byte[this.encCipher.getOutputSize(res.length)];
            this.encCipher.update(res, 0, res.length, rez);
            ConnectionState.incSequenceNumber(this.write_seq_num);
            return rez;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new AlertException((byte) 80, new SSLProtocolException("Error during the encryption"));
        }
    }

    protected byte[] decrypt(byte type, byte[] fragment, int offset, int len) {
        byte[] content;
        byte[] data = this.decCipher.update(fragment, offset, len);
        if (this.is_block_cipher) {
            byte padding_length = data[data.length - 1];
            for (byte i = (byte) 0; i < padding_length; i++) {
                if (data[(data.length - 2) - i] != padding_length) {
                    throw new AlertException((byte) 21, new SSLProtocolException("Received message has bad padding"));
                }
            }
            content = new byte[(((data.length - this.hash_size) - padding_length) - 1)];
        } else {
            content = new byte[(data.length - this.hash_size)];
        }
        this.mac_material_part[0] = type;
        this.mac_material_part[1] = (byte) ((65280 & content.length) >> 8);
        this.mac_material_part[2] = (byte) (content.length & 255);
        this.messageDigest.update(this.mac_read_secret);
        this.messageDigest.update(this.pad_1);
        this.messageDigest.update(this.read_seq_num);
        this.messageDigest.update(this.mac_material_part);
        this.messageDigest.update(data, 0, content.length);
        byte[] mac_value = this.messageDigest.digest();
        this.messageDigest.update(this.mac_read_secret);
        this.messageDigest.update(this.pad_2);
        this.messageDigest.update(mac_value);
        mac_value = this.messageDigest.digest();
        if (this.logger != null) {
            this.logger.println("Decrypted:");
            this.logger.print(data);
            this.logger.println("Expected mac value:");
            this.logger.print(mac_value);
        }
        for (int i2 = 0; i2 < this.hash_size; i2++) {
            if (mac_value[i2] != data[content.length + i2]) {
                throw new AlertException(Handshake.FINISHED, new SSLProtocolException("Bad record MAC"));
            }
        }
        System.arraycopy(data, 0, content, 0, content.length);
        ConnectionState.incSequenceNumber(this.read_seq_num);
        return content;
    }

    protected void shutdown() {
        Arrays.fill(this.mac_write_secret, (byte) 0);
        Arrays.fill(this.mac_read_secret, (byte) 0);
        super.shutdown();
    }
}
