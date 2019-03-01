package de.tsenger.androsmex.pace;

public abstract class Pace {
    protected byte[] nonce_s = null;
    protected byte[] sharedSecret_K = null;
    protected byte[] sharedSecret_P = null;

    public abstract byte[] getSharedSecret_K(byte[] bArr);

    public abstract byte[] getX1(byte[] bArr);

    public abstract byte[] getX2(byte[] bArr);
}
