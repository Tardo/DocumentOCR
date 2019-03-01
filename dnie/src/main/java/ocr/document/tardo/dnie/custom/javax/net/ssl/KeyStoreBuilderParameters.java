package custom.javax.net.ssl;

import java.security.KeyStore.Builder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KeyStoreBuilderParameters implements ManagerFactoryParameters {
    private final List<Builder> ksbuilders;

    public KeyStoreBuilderParameters(Builder builder) {
        this.ksbuilders = Collections.singletonList(builder);
    }

    public KeyStoreBuilderParameters(List parameters) {
        if (parameters == null) {
            throw new NullPointerException("Builders list is null");
        } else if (parameters.isEmpty()) {
            throw new IllegalArgumentException("Builders list is empty");
        } else {
            this.ksbuilders = Collections.unmodifiableList(new ArrayList(parameters));
        }
    }

    public List getParameters() {
        return this.ksbuilders;
    }
}
