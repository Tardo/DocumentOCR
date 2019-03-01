package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class DelegatedTask implements Runnable {
    private final PrivilegedExceptionAction<Void> action;
    private final AccessControlContext context;
    private final HandshakeProtocol handshaker;

    public DelegatedTask(PrivilegedExceptionAction<Void> action, HandshakeProtocol handshaker, AccessControlContext context) {
        this.action = action;
        this.handshaker = handshaker;
        this.context = context;
    }

    public void run() {
        synchronized (this.handshaker) {
            try {
                AccessController.doPrivileged(this.action, this.context);
            } catch (PrivilegedActionException e) {
                this.handshaker.delegatedTaskErr = e.getException();
            } catch (RuntimeException e2) {
                this.handshaker.delegatedTaskErr = e2;
            }
        }
    }
}
