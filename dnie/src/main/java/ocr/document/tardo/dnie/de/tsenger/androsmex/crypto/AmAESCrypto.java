package de.tsenger.androsmex.crypto;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.Mac;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class AmAESCrypto extends AmCryptoProvider {
    public static int blockSize = 16;
    private byte[] IV = null;
    private byte[] keyBytes = null;
    private KeyParameter keyP = null;
    private byte[] sscBytes = null;

    private void initCiphers(byte[] key, byte[] iv) {
        this.keyBytes = new byte[key.length];
        System.arraycopy(key, 0, this.keyBytes, 0, key.length);
        this.keyP = new KeyParameter(this.keyBytes);
        this.IV = new byte[blockSize];
        System.arraycopy(iv, 0, this.IV, 0, this.IV.length);
        this.encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()), new ISO7816d4Padding());
        this.decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()), new ISO7816d4Padding());
        ParametersWithIV parameterIV = new ParametersWithIV(this.keyP, this.IV);
        this.encryptCipher.init(true, parameterIV);
        this.decryptCipher.init(false, parameterIV);
    }

    public void init(byte[] keyBytes, byte[] ssc) {
        this.sscBytes = (byte[]) ssc.clone();
        initCiphers(keyBytes, encryptBlock(keyBytes, this.sscBytes));
    }

    public byte[] getMAC(byte[] data) {
        byte[] n = new byte[(this.sscBytes.length + data.length)];
        System.arraycopy(this.sscBytes, 0, n, 0, this.sscBytes.length);
        System.arraycopy(data, 0, n, this.sscBytes.length, data.length);
        n = addPadding(n);
        Mac mac = new CMac(new AESFastEngine(), 64);
        mac.init(this.keyP);
        mac.update(n, 0, n.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    public byte[] getMAC(byte[] key, byte[] data) {
        Mac mac = new CMac(new AESFastEngine(), 64);
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return out;
    }

    public byte[] decryptBlock(byte[] key, byte[] z) {
        byte[] s = new byte[blockSize];
        KeyParameter encKey = new KeyParameter(key);
        BlockCipher cipher = new AESFastEngine();
        cipher.init(false, encKey);
        cipher.processBlock(z, 0, s, 0);
        return s;
    }

    public byte[] encryptBlock(byte[] key, byte[] z) {
        byte[] s = new byte[blockSize];
        KeyParameter encKey = new KeyParameter(key);
        BlockCipher cipher = new AESFastEngine();
        cipher.init(true, encKey);
        cipher.processBlock(z, 0, s, 0);
        return s;
    }

    public int getBlockSize() {
        return blockSize;
    }
}
