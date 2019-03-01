package org.spongycastle.jce.provider;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

/* compiled from: BrokenPBE */
class OldPKCS12ParametersGenerator extends PBEParametersGenerator {
    public static final int IV_MATERIAL = 2;
    public static final int KEY_MATERIAL = 1;
    public static final int MAC_MATERIAL = 3;
    private Digest digest;
    /* renamed from: u */
    private int f422u;
    /* renamed from: v */
    private int f423v;

    public OldPKCS12ParametersGenerator(Digest digest) {
        this.digest = digest;
        if (digest instanceof MD5Digest) {
            this.f422u = 16;
            this.f423v = 64;
        } else if (digest instanceof SHA1Digest) {
            this.f422u = 20;
            this.f423v = 64;
        } else if (digest instanceof RIPEMD160Digest) {
            this.f422u = 20;
            this.f423v = 64;
        } else {
            throw new IllegalArgumentException("Digest " + digest.getAlgorithmName() + " unsupported");
        }
    }

    private void adjust(byte[] a, int aOff, byte[] b) {
        int x = ((b[b.length - 1] & 255) + (a[(b.length + aOff) - 1] & 255)) + 1;
        a[(b.length + aOff) - 1] = (byte) x;
        x >>>= 8;
        for (int i = b.length - 2; i >= 0; i--) {
            x += (b[i] & 255) + (a[aOff + i] & 255);
            a[aOff + i] = (byte) x;
            x >>>= 8;
        }
    }

    private byte[] generateDerivedKey(int idByte, int n) {
        int i;
        byte[] S;
        byte[] P;
        byte[] D = new byte[this.f423v];
        byte[] dKey = new byte[n];
        for (i = 0; i != D.length; i++) {
            D[i] = (byte) idByte;
        }
        if (this.salt == null || this.salt.length == 0) {
            S = new byte[0];
        } else {
            S = new byte[(this.f423v * (((this.salt.length + this.f423v) - 1) / this.f423v))];
            for (i = 0; i != S.length; i++) {
                S[i] = this.salt[i % this.salt.length];
            }
        }
        if (this.password == null || this.password.length == 0) {
            P = new byte[0];
        } else {
            P = new byte[(this.f423v * (((this.password.length + this.f423v) - 1) / this.f423v))];
            for (i = 0; i != P.length; i++) {
                P[i] = this.password[i % this.password.length];
            }
        }
        byte[] I = new byte[(S.length + P.length)];
        System.arraycopy(S, 0, I, 0, S.length);
        System.arraycopy(P, 0, I, S.length, P.length);
        byte[] B = new byte[this.f423v];
        int c = ((this.f422u + n) - 1) / this.f422u;
        for (i = 1; i <= c; i++) {
            int j;
            byte[] A = new byte[this.f422u];
            this.digest.update(D, 0, D.length);
            this.digest.update(I, 0, I.length);
            this.digest.doFinal(A, 0);
            for (j = 1; j != this.iterationCount; j++) {
                this.digest.update(A, 0, A.length);
                this.digest.doFinal(A, 0);
            }
            for (j = 0; j != B.length; j++) {
                B[i] = A[j % A.length];
            }
            for (j = 0; j != I.length / this.f423v; j++) {
                adjust(I, this.f423v * j, B);
            }
            if (i == c) {
                System.arraycopy(A, 0, dKey, (i - 1) * this.f422u, dKey.length - ((i - 1) * this.f422u));
            } else {
                System.arraycopy(A, 0, dKey, (i - 1) * this.f422u, A.length);
            }
        }
        return dKey;
    }

    public CipherParameters generateDerivedParameters(int keySize) {
        keySize /= 8;
        return new KeyParameter(generateDerivedKey(1, keySize), 0, keySize);
    }

    public CipherParameters generateDerivedParameters(int keySize, int ivSize) {
        keySize /= 8;
        ivSize /= 8;
        byte[] dKey = generateDerivedKey(1, keySize);
        return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), generateDerivedKey(2, ivSize), 0, ivSize);
    }

    public CipherParameters generateDerivedMacParameters(int keySize) {
        keySize /= 8;
        return new KeyParameter(generateDerivedKey(3, keySize), 0, keySize);
    }
}
