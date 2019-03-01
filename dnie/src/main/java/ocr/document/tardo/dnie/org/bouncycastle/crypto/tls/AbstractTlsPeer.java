package org.bouncycastle.crypto.tls;

public abstract class AbstractTlsPeer implements TlsPeer {
    public void notifyAlertRaised(short s, short s2, String str, Exception exception) {
    }

    public void notifyAlertReceived(short s, short s2) {
    }
}
