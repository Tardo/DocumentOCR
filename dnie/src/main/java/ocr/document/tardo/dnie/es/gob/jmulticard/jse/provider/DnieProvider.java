package es.gob.jmulticard.jse.provider;

import android.nfc.Tag;
import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.SocketPermission;
import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class DnieProvider extends Provider {
    private static final String ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY = "es.gob.jmulticard.jse.provider.MrtdPrivateKey";
    private static final String ES_GOB_JMULTICARD_CARD_DNIE_DNIE_PRIVATE_KEY = "es.gob.jmulticard.jse.provider.DniePrivateKey";
    private static final String INFO = "Proveedor para el DNIe";
    private static final String NAME = "DNIeJCAProvider";
    private static final String NONEWITH_RSA = "NONEwithRSA";
    public static final String SHA1WITH_RSA = "SHA1withRSA";
    private static final String SHA256WITH_RSA = "SHA256withRSA";
    private static final String SHA384WITH_RSA = "SHA384withRSA";
    private static final String SHA512WITH_RSA = "SHA512withRSA";
    private static final double VERSION = 0.2d;
    public static String mMrtdCAN = null;
    public static Tag mNFCTag = null;
    private static final long serialVersionUID = -1046745919235177156L;

    /* renamed from: es.gob.jmulticard.jse.provider.DnieProvider$1 */
    class C00801 implements PrivilegedAction<Void> {
        C00801() {
        }

        public Void run() {
            if (!(System.getProperty("java.vm.name").equalsIgnoreCase("Dalvik") || (System.getSecurityManager() instanceof DnieSecurityManager))) {
            }
            return null;
        }
    }

    private static final class DnieSecurityManager extends SecurityManager {
        private static final List<String> ALLOWED_MEMBER_ACCESS_PREFIXES = new ArrayList(4);
        private static final Set<String> DENIED_PREMISSIONS_NAMES = new HashSet(8);
        private final SecurityManager sm;

        DnieSecurityManager(SecurityManager sm) {
            this.sm = sm;
        }

        public void checkAccept(String host, int port) {
            if (this.sm != null) {
                this.sm.checkAccept(host, port);
            }
        }

        public void checkAccess(Thread t) {
            if (this.sm != null) {
                this.sm.checkAccess(t);
            }
        }

        public void checkAccess(ThreadGroup g) {
            if (this.sm != null) {
                this.sm.checkAccess(g);
            }
        }

        public void checkAwtEventQueueAccess() {
            if (this.sm != null) {
                this.sm.checkAwtEventQueueAccess();
            }
        }

        public void checkConnect(String host, int port) {
            if (this.sm != null) {
                this.sm.checkConnect(host, port);
            }
        }

        public void checkConnect(String host, int port, Object context) {
            if (this.sm != null) {
                this.sm.checkConnect(host, port, context);
            }
        }

        public void checkCreateClassLoader() {
            if (this.sm != null) {
                this.sm.checkCreateClassLoader();
            }
        }

        public void checkDelete(String file) {
            if (this.sm != null) {
                this.sm.checkDelete(file);
            }
        }

        public void checkExec(String cmd) {
            if (this.sm != null) {
                this.sm.checkExec(cmd);
            }
        }

        public void checkExit(int status) {
            if (this.sm != null) {
                this.sm.checkExit(status);
            }
        }

        public void checkLink(String lib) {
            if (this.sm != null) {
                this.sm.checkLink(lib);
            }
        }

        public void checkListen(int port) {
            if (this.sm != null) {
                this.sm.checkListen(port);
            }
        }

        static {
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.asn1.der");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.ui.passwordcallback");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.jse.provider.DnieProvider");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.jse.provider.DnieKeyStoreImpl");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.jse.provider.DnieSignatureImpl");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl");
            ALLOWED_MEMBER_ACCESS_PREFIXES.add("es.gob.jmulticard.jse.provider.MrtdSignatureImpl");
            DENIED_PREMISSIONS_NAMES.add("setPolicy");
            DENIED_PREMISSIONS_NAMES.add("clearProviderProperties.DNIeJCAProvider");
            DENIED_PREMISSIONS_NAMES.add("putProviderProperty.DNIeJCAProvider");
            DENIED_PREMISSIONS_NAMES.add("removeProviderProperty.DNIeJCAProvider");
            DENIED_PREMISSIONS_NAMES.add("readDisplayPixels");
            DENIED_PREMISSIONS_NAMES.add("setSecurityManager");
        }

        public void checkMemberAccess(Class<?> clazz, int which) {
            super.checkMemberAccess(clazz, which);
            if (clazz.getName().startsWith("es.gob.jmulticard")) {
                for (String classPrefix : ALLOWED_MEMBER_ACCESS_PREFIXES) {
                    if (clazz.getName().startsWith(classPrefix)) {
                        if (this.sm != null) {
                            this.sm.checkMemberAccess(clazz, which);
                            return;
                        }
                        return;
                    }
                }
                throw new SecurityException("No se permite el acceso por reflexion a esta clase: " + clazz);
            } else if (this.sm != null) {
                this.sm.checkMemberAccess(clazz, which);
            }
        }

        public void checkMulticast(InetAddress maddr) {
            if (this.sm != null) {
                this.sm.checkMulticast(maddr);
            }
        }

        public void checkMulticast(InetAddress maddr, byte ttl) {
            if (this.sm != null) {
                this.sm.checkPermission(new SocketPermission(maddr.getHostAddress(), "accept,connect"));
            }
        }

        public void checkPackageAccess(String pkg) {
            super.checkPackageAccess(pkg);
            if (this.sm != null) {
                this.sm.checkPackageAccess(pkg);
            }
        }

        public void checkPackageDefinition(String pkg) {
            super.checkPackageDefinition(pkg);
            if (pkg != null && pkg.startsWith("es.gob.jmulticard")) {
                throw new SecurityException("No se permite la creacion de clases en este paquete");
            } else if (this.sm != null) {
                this.sm.checkPackageDefinition(pkg);
            }
        }

        public void checkPermission(Permission perm) {
            if (DENIED_PREMISSIONS_NAMES.contains(perm.getName())) {
                throw new SecurityException("Operacion no permitida: " + perm);
            } else if (this.sm != null) {
                this.sm.checkPermission(perm);
            }
        }

        public void checkPermission(Permission perm, Object context) {
            if (this.sm != null) {
                this.sm.checkPermission(perm, context);
            }
        }

        public void checkPrintJobAccess() {
            if (this.sm != null) {
                this.sm.checkPrintJobAccess();
            }
        }

        public void checkPropertiesAccess() {
            if (this.sm != null) {
                this.sm.checkPropertiesAccess();
            }
        }

        public void checkPropertyAccess(String key) {
            if (this.sm != null) {
                this.sm.checkPropertyAccess(key);
            }
        }

        public void checkRead(FileDescriptor fd) {
            if (this.sm != null) {
                this.sm.checkRead(fd);
            }
        }

        public void checkRead(String file) {
            if (this.sm != null) {
                this.sm.checkRead(file);
            }
        }

        public void checkRead(String file, Object context) {
            if (this.sm != null) {
                this.sm.checkRead(file, context);
            }
        }

        public void checkSecurityAccess(String target) {
            if (this.sm != null) {
                this.sm.checkSecurityAccess(target);
            }
        }

        public void checkSetFactory() {
            if (this.sm != null) {
                this.sm.checkSetFactory();
            }
        }

        public void checkSystemClipboardAccess() {
            if (this.sm != null) {
                this.sm.checkSystemClipboardAccess();
            }
        }

        public boolean checkTopLevelWindow(Object window) {
            if (this.sm != null) {
                return this.sm.checkTopLevelWindow(window);
            }
            return true;
        }

        public void checkWrite(FileDescriptor fd) {
            if (this.sm != null) {
                this.sm.checkWrite(fd);
            }
        }

        public void checkWrite(String file) {
            if (this.sm != null) {
                this.sm.checkWrite(file);
            }
        }
    }

    public void setProviderCan(String sNewCAN) {
        mMrtdCAN = sNewCAN;
    }

    public String getProviderCan() {
        return mMrtdCAN;
    }

    public void setProviderTag(Tag commIF) {
        mNFCTag = commIF;
    }

    public Tag getProviderTag() {
        return mNFCTag;
    }

    public DnieProvider() {
        super(NAME, VERSION, INFO);
        AccessController.doPrivileged(new C00801());
        put("KeyStore.DNI", "es.gob.jmulticard.jse.provider.DnieKeyStoreImpl");
        put("KeyStore.DNIe", "es.gob.jmulticard.jse.provider.DnieKeyStoreWithDataImpl");
        put("KeyStore.MRTD", "es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl");
        put("Signature.SHA1withRSAespecial", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$Sha1");
        put("Signature.SHA1withRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$Sha1");
        put("Signature.SHA256withRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$Sha256");
        put("Signature.SHA384withRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$Sha384");
        put("Signature.SHA512withRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$Sha512");
        put("Signature.NONEwithRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$None");
        put("Signature.MRTDNONEwithRSA", "es.gob.jmulticard.jse.provider.MrtdSignatureImpl$None");
        put("Signature.SHA1withRSA SupportedKeyClasses", ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY);
        put("Signature.SHA256withRSA SupportedKeyClasses", ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY);
        put("Signature.SHA384withRSA SupportedKeyClasses", ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY);
        put("Signature.SHA512withRSA SupportedKeyClasses", ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY);
        put("Signature.NONEwithRSA SupportedKeyClasses", ES_GOB_JMULTICARD_CARD_DNIE_DMRTD_PRIVATE_KEY);
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5", SHA1WITH_RSA);
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", SHA1WITH_RSA);
        put("Alg.Alias.Signature.1.3.14.3.2.29", SHA1WITH_RSA);
        put("Alg.Alias.Signature.SHAwithRSA", SHA1WITH_RSA);
        put("Alg.Alias.Signature.SHA-1withRSA", SHA1WITH_RSA);
        put("Alg.Alias.Signature.SHA1withRSAEncryption", SHA1WITH_RSA);
        put("Alg.Alias.Signature.SHA-1withRSAEncryption", SHA1WITH_RSA);
        put("Alg.Alias.Signature.1.2.840.113549.1.1.11", SHA256WITH_RSA);
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", SHA256WITH_RSA);
        put("Alg.Alias.Signature.SHA-256withRSA", SHA256WITH_RSA);
        put("Alg.Alias.Signature.SHA-256withRSAEncryption", SHA256WITH_RSA);
        put("Alg.Alias.Signature.SHA256withRSAEncryption", SHA256WITH_RSA);
        put("Alg.Alias.Signature.1.2.840.113549.1.1.12", SHA384WITH_RSA);
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", SHA384WITH_RSA);
        put("Alg.Alias.Signature.SHA-384withRSA", SHA384WITH_RSA);
        put("Alg.Alias.Signature.SHA-384withRSAEncryption", SHA384WITH_RSA);
        put("Alg.Alias.Signature.SHA384withRSAEncryption", SHA384WITH_RSA);
        put("Alg.Alias.Signature.1.2.840.113549.1.1.13", SHA512WITH_RSA);
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", SHA512WITH_RSA);
        put("Alg.Alias.Signature.SHA-512withRSA", SHA512WITH_RSA);
        put("Alg.Alias.Signature.SHA-512withRSAEncryption", SHA512WITH_RSA);
        put("Alg.Alias.Signature.SHA512withRSAEncryption", SHA512WITH_RSA);
        put("Alg.Alias.Signature.NONEwithRSA", NONEWITH_RSA);
        put("Alg.Alias.Signature.NONEwithRSAEncryption", NONEWITH_RSA);
    }
}
