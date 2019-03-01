package de.tsenger.androsmex.crypto;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.Mac;
import org.spongycastle.crypto.engines.DESEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.macs.ISO9797Alg3Mac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class AmDESCrypto extends AmCryptoProvider {
    public static int blockSize = 8;
    private byte[] IV = null;
    private byte[] keyBytes;
    private KeyParameter keyP = null;
    private byte[] sscBytes = null;

    private void initCiphers(byte[] key, byte[] iv) {
        this.keyBytes = new byte[key.length];
        System.arraycopy(key, 0, this.keyBytes, 0, key.length);
        this.IV = new byte[blockSize];
        System.arraycopy(iv, 0, this.IV, 0, iv.length);
        this.keyP = new KeyParameter(this.keyBytes);
        this.encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()), new ISO7816d4Padding());
        this.decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()), new ISO7816d4Padding());
        ParametersWithIV parameterIV = new ParametersWithIV(this.keyP, this.IV);
        this.encryptCipher.init(true, parameterIV);
        this.decryptCipher.init(false, parameterIV);
    }

    public void init(byte[] keyBytes, byte[] ssc) {
        this.sscBytes = (byte[]) ssc.clone();
        initCiphers(keyBytes, new byte[blockSize]);
    }

    public byte[] getMAC(byte[] data) {
        byte[] n = new byte[(data.length + 8)];
        System.arraycopy(this.sscBytes, 0, n, 0, 8);
        System.arraycopy(data, 0, n, 8, data.length);
        Mac mac = new ISO9797Alg3Mac(new DESEngine(), 64, new ISO7816d4Padding());
        mac.init(new ParametersWithIV(this.keyP, this.IV));
        mac.update(n, 0, n.length);
        byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return out;
    }

    public byte[] decryptBlock(byte[] key, byte[] z) {
        byte[] s = new byte[16];
        KeyParameter encKey = new KeyParameter(key);
        BlockCipher cipher = new DESedeEngine();
        cipher.init(false, encKey);
        cipher.processBlock(z, 0, s, 0);
        return s;
    }

    public byte[] getMAC(byte[] key, byte[] data) {
        Mac mac = new ISO9797Alg3Mac(new DESEngine(), 64, new ISO7816d4Padding());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return out;
    }

    public int getBlockSize() {
        return blockSize;
    }
}
