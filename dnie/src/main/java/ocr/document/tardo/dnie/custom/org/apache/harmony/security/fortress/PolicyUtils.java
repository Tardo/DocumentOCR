package custom.org.apache.harmony.security.fortress;

import custom.org.apache.harmony.security.Util;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessController;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

public class PolicyUtils {
    public static final String FALSE = "false";
    private static final Class[] NO_ARGS = new Class[0];
    private static final Class[] ONE_ARGS = new Class[]{String.class};
    public static final String POLICY_ALLOW_DYNAMIC = "policy.allowSystemProperty";
    public static final String POLICY_EXPAND = "policy.expandProperties";
    public static final String TRUE = "true";
    private static final Class[] TWO_ARGS = new Class[]{String.class, String.class};

    public static class ExpansionFailedException extends Exception {
        private static final long serialVersionUID = 2869748055182612000L;

        public ExpansionFailedException(String message) {
            super(message);
        }

        public ExpansionFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public interface GeneralExpansionHandler {
        String resolve(String str, String str2) throws ExpansionFailedException;
    }

    public static class ProviderLoader<T> implements PrivilegedAction<T> {
        private Class<T> expectedType;
        private String key;

        public ProviderLoader(String key, Class<T> expected) {
            this.key = key;
            this.expectedType = expected;
        }

        public T run() {
            SecurityException se;
            Object klassName = Security.getProperty(this.key);
            if (klassName == null || klassName.length() == 0) {
                throw new SecurityException(Messages.getString("security.14C", this.key));
            }
            try {
                Class<?> klass = Class.forName(klassName, true, Thread.currentThread().getContextClassLoader());
                if (this.expectedType == null || !klass.isAssignableFrom(this.expectedType)) {
                    return klass.newInstance();
                }
                throw new SecurityException(Messages.getString("security.14D", klassName, this.expectedType.getName()));
            } catch (SecurityException se2) {
                throw se2;
            } catch (Exception e) {
                se2 = new SecurityException(Messages.getString("security.14E", klassName));
                se2.initCause(e);
                throw se2;
            }
        }
    }

    public static class SecurityPropertyAccessor implements PrivilegedAction<String> {
        private String key;

        public SecurityPropertyAccessor(String key) {
            this.key = key;
        }

        public PrivilegedAction<String> key(String key) {
            this.key = key;
            return this;
        }

        public String run() {
            return Security.getProperty(this.key);
        }
    }

    public static class SystemKit implements PrivilegedAction<Properties> {
        public Properties run() {
            return System.getProperties();
        }
    }

    public static class SystemPropertyAccessor implements PrivilegedAction<String> {
        public String key;

        public SystemPropertyAccessor(String key) {
            this.key = key;
        }

        public PrivilegedAction<String> key(String key) {
            this.key = key;
            return this;
        }

        public String run() {
            return System.getProperty(this.key);
        }
    }

    public static class URLLoader implements PrivilegedExceptionAction<InputStream> {
        public URL location;

        public URLLoader(URL location) {
            this.location = location;
        }

        public InputStream run() throws Exception {
            return this.location.openStream();
        }
    }

    private PolicyUtils() {
    }

    public static String expand(String str, Properties properties) throws ExpansionFailedException {
        String START_MARK = "${";
        String END_MARK = "}";
        int START_OFFSET = "${".length();
        int END_OFFSET = "}".length();
        StringBuilder result = new StringBuilder(str);
        int start = result.indexOf("${");
        while (start >= 0) {
            int end = result.indexOf("}", start);
            if (end >= 0) {
                Object key = result.substring(start + START_OFFSET, end);
                String value = properties.getProperty(key);
                if (value != null) {
                    result.replace(start, end + END_OFFSET, value);
                    start += value.length();
                } else {
                    throw new ExpansionFailedException(Messages.getString("security.14F", key));
                }
            }
            start = result.indexOf("${", start);
        }
        return result.toString();
    }

    public static String expandURL(String str, Properties properties) throws ExpansionFailedException {
        return expand(str, properties).replace(File.separatorChar, '/');
    }

    public static URL normalizeURL(URL codebase) {
        if (codebase == null || !"file".equals(codebase.getProtocol())) {
            return codebase;
        }
        try {
            if (codebase.getHost().length() != 0) {
                return codebase.toURI().normalize().toURL();
            }
            String path = codebase.getFile();
            if (path.length() == 0) {
                path = "*";
            }
            return filePathToURI(new File(path).getAbsolutePath()).normalize().toURL();
        } catch (Exception e) {
            return codebase;
        }
    }

    public static URI filePathToURI(String path) throws URISyntaxException {
        path = path.replace(File.separatorChar, '/');
        if (path.startsWith("/")) {
            return new URI("file", null, path, null, null);
        }
        return new URI("file", null, new StringBuilder(path.length() + 1).append('/').append(path).toString(), null, null);
    }

    public static String expandGeneral(String str, GeneralExpansionHandler handler) throws ExpansionFailedException {
        String START_MARK = "${{";
        String END_MARK = "}}";
        int START_OFFSET = "${{".length();
        int END_OFFSET = "}}".length();
        StringBuilder result = new StringBuilder(str);
        int start = result.indexOf("${{");
        while (start >= 0) {
            int end = result.indexOf("}}", start);
            if (end >= 0) {
                String protocol;
                String key = result.substring(start + START_OFFSET, end);
                int separator = key.indexOf(58);
                if (separator >= 0) {
                    protocol = key.substring(0, separator);
                } else {
                    protocol = key;
                }
                String value = handler.resolve(protocol, separator >= 0 ? key.substring(separator + 1) : null);
                result.replace(start, end + END_OFFSET, value);
                start += value.length();
            }
            start = result.indexOf("${{", start);
        }
        return result.toString();
    }

    public static boolean canExpandProperties() {
        return !Util.equalsIgnoreCase(FALSE, (String) AccessController.doPrivileged(new SecurityPropertyAccessor(POLICY_EXPAND)));
    }

    public static URL[] getPolicyURLs(Properties system, String systemUrlKey, String securityUrlPrefix) {
        String location;
        SecurityPropertyAccessor security = new SecurityPropertyAccessor(null);
        List<URL> urls = new ArrayList();
        boolean dynamicOnly = false;
        URL dynamicURL = null;
        if (!Util.equalsIgnoreCase(FALSE, (String) AccessController.doPrivileged(security.key(POLICY_ALLOW_DYNAMIC)))) {
            location = system.getProperty(systemUrlKey);
            if (location != null) {
                if (location.startsWith("=")) {
                    dynamicOnly = true;
                    location = location.substring(1);
                }
                try {
                    location = expandURL(location, system);
                    final File f = new File(location);
                    dynamicURL = (URL) AccessController.doPrivileged(new PrivilegedExceptionAction<URL>() {
                        public URL run() throws Exception {
                            if (f.exists()) {
                                return f.toURI().toURL();
                            }
                            return null;
                        }
                    });
                    if (dynamicURL == null) {
                        dynamicURL = new URL(location);
                    }
                } catch (Exception e) {
                }
            }
        }
        if (!dynamicOnly) {
            int i = 1;
            while (true) {
                int i2 = i + 1;
                location = (String) AccessController.doPrivileged(security.key(i));
                if (location == null) {
                    break;
                }
                try {
                    URL anURL = new URL(expandURL(location, system));
                    if (anURL != null) {
                        urls.add(anURL);
                    }
                } catch (Exception e2) {
                }
                i = i2;
            }
        }
        if (dynamicURL != null) {
            urls.add(dynamicURL);
        }
        return (URL[]) urls.toArray(new URL[urls.size()]);
    }

    public static PermissionCollection toPermissionCollection(Collection<Permission> perms) {
        Permissions pc = new Permissions();
        if (perms != null) {
            for (Permission element : perms) {
                pc.add(element);
            }
        }
        return pc;
    }

    public static Permission instantiatePermission(Class<?> targetType, String targetName, String targetActions) throws Exception {
        Class[][] argTypes = null;
        Object[][] args = null;
        if (targetActions != null) {
            argTypes = new Class[][]{TWO_ARGS, ONE_ARGS, NO_ARGS};
            args = new Object[3][];
            args[0] = new Object[]{targetName, targetActions};
            args[1] = new Object[]{targetName};
            args[2] = new Object[0];
        } else if (targetName != null) {
            argTypes = new Class[][]{ONE_ARGS, TWO_ARGS, NO_ARGS};
            args = new Object[3][];
            args[0] = new Object[]{targetName};
            args[1] = new Object[]{targetName, targetActions};
            args[2] = new Object[0];
        } else {
            argTypes = new Class[][]{NO_ARGS, ONE_ARGS, TWO_ARGS};
            args = new Object[3][];
            args[1] = new Object[]{targetName};
            args[2] = new Object[]{targetName, targetActions};
        }
        int i = 0;
        while (i < argTypes.length) {
            try {
                return (Permission) targetType.getConstructor(argTypes[i]).newInstance(args[i]);
            } catch (NoSuchMethodException e) {
                i++;
            }
        }
        throw new IllegalArgumentException(Messages.getString("security.150", (Object) targetType));
    }

    public static boolean matchSubset(Object[] what, Object[] where) {
        if (what == null) {
            return true;
        }
        for (int i = 0; i < what.length; i++) {
            if (what[i] != null) {
                if (where == null) {
                    return false;
                }
                boolean found = false;
                for (Object equals : where) {
                    if (what[i].equals(equals)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
        }
        return true;
    }
}
