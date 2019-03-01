package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.Util;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;

public class Engine {
    public static SecurityAccess door;
    private String lastAlgorithm;
    public Provider provider;
    private int refreshNumber;
    private Service returnedService;
    private String serviceName;
    public Object spi;

    public Engine(String service) {
        this.serviceName = service;
    }

    public synchronized void getInstance(String algorithm, Object param) throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException(Messages.getString("security.149"));
        }
        Service serv;
        Services.refresh();
        if (this.returnedService != null && Util.equalsIgnoreCase(algorithm, this.lastAlgorithm) && this.refreshNumber == Services.refreshNumber) {
            serv = this.returnedService;
        } else if (Services.isEmpty()) {
            throw new NoSuchAlgorithmException(Messages.getString("security.14A", this.serviceName, algorithm));
        } else {
            serv = Services.getService(this.serviceName + "." + Util.toUpperCase(algorithm));
            if (serv == null) {
                throw new NoSuchAlgorithmException(Messages.getString("security.14A", this.serviceName, algorithm));
            }
            this.returnedService = serv;
            this.lastAlgorithm = algorithm;
            this.refreshNumber = Services.refreshNumber;
        }
        this.spi = serv.newInstance(param);
        this.provider = serv.getProvider();
    }

    public synchronized void getInstance(String algorithm, Provider provider, Object param) throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException(Messages.getString("security.14B", this.serviceName));
        }
        Service serv = provider.getService(this.serviceName, algorithm);
        if (serv == null) {
            throw new NoSuchAlgorithmException(Messages.getString("security.14A", this.serviceName, algorithm));
        }
        this.spi = serv.newInstance(param);
        this.provider = provider;
    }
}
