package org.bouncycastle.crypto.tls;

public interface TlsPeer {
    void notifyAlertRaised(short s, short s2, String str, Exception exception);

    void notifyAlertReceived(short s, short s2);
}
