package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLProtocolException;

public class ConnectionStateTLS extends ConnectionState {
    private static byte[] CLIENT_WRITE_KEY_LABEL = new byte[]{(byte) 99, (byte) 108, (byte) 105, (byte) 101, (byte) 110, (byte) 116, (byte) 32, (byte) 119, (byte) 114, (byte) 105, (byte) 116, (byte) 101, (byte) 32, (byte) 107, (byte) 101, (byte) 121};
    private static byte[] IV_BLOCK_LABEL = new byte[]{(byte) 73, (byte) 86, (byte) 32, (byte) 98, (byte) 108, (byte) 111, (byte) 99, (byte) 107};
    private static byte[] KEY_EXPANSION_LABEL = new byte[]{(byte) 107, (byte) 101, (byte) 121, (byte) 32, (byte) 101, (byte) 120, (byte) 112, (byte) 97, (byte) 110, (byte) 115, (byte) 105, (byte) 111, (byte) 110};
    private static byte[] SERVER_WRITE_KEY_LABEL = new byte[]{(byte) 115, (byte) 101, (byte) 114, (byte) 118, (byte) 101, (byte) 114, (byte) 32, (byte) 119, (byte) 114, (byte) 105, (byte) 116, (byte) 101, (byte) 32, (byte) 107, (byte) 101, (byte) 121};
    private final Mac decMac;
    private final Mac encMac;
    private final byte[] mac_material_header = new byte[]{(byte) 0, (byte) 3, (byte) 1, (byte) 0, (byte) 0};

    protected ConnectionStateTLS(SSLSessionImpl session) {
        byte[] bArr = new byte[5];
        try {
            CipherSuite cipherSuite = session.cipherSuite;
            this.hash_size = cipherSuite.getMACLength();
            boolean is_exportabe = cipherSuite.isExportable();
            int key_size = is_exportabe ? cipherSuite.keyMaterial : cipherSuite.expandedKeyMaterial;
            int iv_size = cipherSuite.getBlockSize();
            String algName = cipherSuite.getBulkEncryptionAlgorithm();
            String macName = cipherSuite.getHmacName();
            if (this.logger != null) {
                this.logger.println("ConnectionStateTLS.create:");
                this.logger.println("  cipher suite name: " + cipherSuite.getName());
                this.logger.println("  encryption alg name: " + algName);
                this.logger.println("  mac alg name: " + macName);
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
            PRF.computePRF(key_block, session.master_secret, KEY_EXPANSION_LABEL, seed);
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
                System.arraycopy(clientRandom, 0, seed, 0, clientRandom.length);
                System.arraycopy(serverRandom, 0, seed, clientRandom.length, serverRandom.length);
                byte[] final_client_key = new byte[cipherSuite.expandedKeyMaterial];
                byte[] final_server_key = new byte[cipherSuite.expandedKeyMaterial];
                PRF.computePRF(final_client_key, client_key, CLIENT_WRITE_KEY_LABEL, seed);
                PRF.computePRF(final_server_key, server_key, SERVER_WRITE_KEY_LABEL, seed);
                client_key = final_client_key;
                server_key = final_server_key;
                if (this.is_block_cipher) {
                    byte[] iv_block = new byte[(iv_size * 2)];
                    PRF.computePRF(iv_block, null, IV_BLOCK_LABEL, seed);
                    clientIV = new IvParameterSpec(iv_block, 0, iv_size);
                    ivParameterSpec = new IvParameterSpec(iv_block, iv_size, iv_size);
                }
            } else if (this.is_block_cipher) {
                clientIV = new IvParameterSpec(key_block, (this.hash_size + key_size) * 2, iv_size);
                ivParameterSpec = new IvParameterSpec(key_block, ((this.hash_size + key_size) * 2) + iv_size, iv_size);
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
                this.logger.print(client_key);
                this.logger.println("server_key");
                this.logger.print(server_key);
                if (clientIV == null) {
                    this.logger.println("no IV.");
                } else {
                    this.logger.println("client_iv");
                    this.logger.print(clientIV.getIV());
                    this.logger.println("server_iv");
                    this.logger.print(serverIV.getIV());
                }
            }
            this.encCipher = Cipher.getInstance(algName);
            this.decCipher = Cipher.getInstance(algName);
            this.encMac = Mac.getInstance(macName);
            this.decMac = Mac.getInstance(macName);
            if (is_client) {
                this.encCipher.init(1, new SecretKeySpec(client_key, algName), clientIV);
                this.decCipher.init(2, new SecretKeySpec(server_key, algName), serverIV);
                this.encMac.init(new SecretKeySpec(client_mac_secret, macName));
                this.decMac.init(new SecretKeySpec(server_mac_secret, macName));
                return;
            }
            this.encCipher.init(1, new SecretKeySpec(server_key, algName), serverIV);
            this.decCipher.init(2, new SecretKeySpec(client_key, algName), clientIV);
            this.encMac.init(new SecretKeySpec(server_mac_secret, macName));
            this.decMac.init(new SecretKeySpec(client_mac_secret, macName));
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
            this.mac_material_header[0] = type;
            this.mac_material_header[3] = (byte) ((65280 & len) >> 8);
            this.mac_material_header[4] = (byte) (len & 255);
            this.encMac.update(this.write_seq_num);
            this.encMac.update(this.mac_material_header);
            this.encMac.update(fragment, offset, len);
            this.encMac.doFinal(res, len);
            if (this.is_block_cipher) {
                Arrays.fill(res, content_mac_length - 1, res.length, (byte) padding_length);
            }
            if (this.logger != null) {
                this.logger.println("SSLRecordProtocol.do_encryption: Generic" + (this.is_block_cipher ? "BlockCipher with padding[" + padding_length + "]:" : "StreamCipher:"));
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
        this.mac_material_header[0] = type;
        this.mac_material_header[3] = (byte) ((65280 & content.length) >> 8);
        this.mac_material_header[4] = (byte) (content.length & 255);
        this.decMac.update(this.read_seq_num);
        this.decMac.update(this.mac_material_header);
        this.decMac.update(data, 0, content.length);
        byte[] mac_value = this.decMac.doFinal();
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
}
