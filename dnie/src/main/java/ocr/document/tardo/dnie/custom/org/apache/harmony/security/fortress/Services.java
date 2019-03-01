package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.Util;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class Services {
    private static boolean needRefresh;
    private static final List<Provider> providers = new ArrayList(20);
    private static final Map<String, Provider> providersNames = new HashMap(20);
    static int refreshNumber = 1;
    private static final Map<String, Service> services = new HashMap(512);

    /* renamed from: custom.org.apache.harmony.security.fortress.Services$1 */
    static class C00491 implements PrivilegedAction<Object> {
        C00491() {
        }

        public Object run() {
            Services.loadProviders();
            return null;
        }
    }

    static {
        AccessController.doPrivileged(new C00491());
    }

    private static void loadProviders() {
        int i = 1;
        ClassLoader cl = ClassLoader.getSystemClassLoader();
        while (true) {
            int i2 = i + 1;
            String providerClassName = Security.getProperty("security.provider." + i);
            if (providerClassName != null) {
                try {
                    Provider p = (Provider) Class.forName(providerClassName.trim(), true, cl).newInstance();
                    providers.add(p);
                    providersNames.put(p.getName(), p);
                    initServiceInfo(p);
                    i = i2;
                } catch (ClassNotFoundException e) {
                    i = i2;
                } catch (IllegalAccessException e2) {
                    i = i2;
                } catch (InstantiationException e3) {
                    i = i2;
                }
            } else {
                Engine.door.renumProviders();
                return;
            }
        }
    }

    public static Provider[] getProviders() {
        return (Provider[]) providers.toArray(new Provider[providers.size()]);
    }

    public static List<Provider> getProvidersList() {
        return new ArrayList(providers);
    }

    public static Provider getProvider(String name) {
        if (name == null) {
            return null;
        }
        return (Provider) providersNames.get(name);
    }

    public static int insertProviderAt(Provider provider, int position) {
        int size = providers.size();
        if (position < 1 || position > size) {
            position = size + 1;
        }
        providers.add(position - 1, provider);
        providersNames.put(provider.getName(), provider);
        setNeedRefresh();
        return position;
    }

    public static void removeProvider(int providerNumber) {
        providersNames.remove(((Provider) providers.remove(providerNumber - 1)).getName());
        setNeedRefresh();
    }

    public static void initServiceInfo(Provider p) {
        StringBuilder sb = new StringBuilder(128);
        for (Service serv : p.getServices()) {
            String type = serv.getType();
            sb.delete(0, sb.length());
            String key = sb.append(type).append(".").append(Util.toUpperCase(serv.getAlgorithm())).toString();
            if (!services.containsKey(key)) {
                services.put(key, serv);
            }
            Iterator<String> it2 = Engine.door.getAliases(serv);
            while (it2.hasNext()) {
                String alias = (String) it2.next();
                sb.delete(0, sb.length());
                key = sb.append(type).append(".").append(Util.toUpperCase(alias)).toString();
                if (!services.containsKey(key)) {
                    services.put(key, serv);
                }
            }
        }
    }

    public static void updateServiceInfo() {
        services.clear();
        for (Provider initServiceInfo : providers) {
            initServiceInfo(initServiceInfo);
        }
        needRefresh = false;
    }

    public static boolean isEmpty() {
        return services.isEmpty();
    }

    public static Service getService(String key) {
        return (Service) services.get(key);
    }

    public static void printServices() {
        refresh();
        for (String key : services.keySet()) {
            System.out.println(key + "=" + services.get(key));
        }
    }

    public static void setNeedRefresh() {
        needRefresh = true;
    }

    public static void refresh() {
        if (needRefresh) {
            refreshNumber++;
            updateServiceInfo();
        }
    }
}
