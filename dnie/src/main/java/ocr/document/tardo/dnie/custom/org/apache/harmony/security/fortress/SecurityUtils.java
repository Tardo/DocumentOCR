package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.AccessControlContext;
import java.util.WeakHashMap;

public final class SecurityUtils {
    private static final WeakHashMap<Thread, AccessControlContext> ACC_CACHE = new WeakHashMap();

    public static void putContext(Thread thread, AccessControlContext context) throws SecurityException {
        if (thread == null) {
            throw new NullPointerException(Messages.getString("security.140"));
        }
        synchronized (ACC_CACHE) {
            if (ACC_CACHE.containsKey(thread)) {
                throw new SecurityException(Messages.getString("security.141"));
            }
            if (context == null) {
                if (ACC_CACHE.containsValue(null)) {
                    throw new Error(Messages.getString("security.142"));
                }
            }
            ACC_CACHE.put(thread, context);
        }
    }

    public static AccessControlContext getContext(Thread thread) throws SecurityException {
        AccessControlContext accessControlContext;
        synchronized (ACC_CACHE) {
            accessControlContext = (AccessControlContext) ACC_CACHE.get(thread);
        }
        return accessControlContext;
    }
}
