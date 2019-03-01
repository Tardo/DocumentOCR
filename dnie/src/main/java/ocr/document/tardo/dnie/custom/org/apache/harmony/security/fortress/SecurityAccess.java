package custom.org.apache.harmony.security.fortress;

import java.security.Provider;
import java.security.Provider.Service;
import java.util.Iterator;

public interface SecurityAccess {
    Iterator<String> getAliases(Service service);

    Service getService(Provider provider, String str);

    void renumProviders();
}
