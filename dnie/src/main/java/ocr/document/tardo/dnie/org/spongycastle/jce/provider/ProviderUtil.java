package org.spongycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Permission;
import org.spongycastle.jce.ProviderConfigurationPermission;
import org.spongycastle.jce.provider.asymmetric.ec.EC5Util;
import org.spongycastle.jce.spec.ECParameterSpec;

public class ProviderUtil {
    private static Permission BC_EC_LOCAL_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, "threadLocalEcImplicitlyCa");
    private static Permission BC_EC_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, "ecImplicitlyCa");
    private static final long MAX_MEMORY = Runtime.getRuntime().maxMemory();
    private static volatile ECParameterSpec ecImplicitCaParams;
    private static ThreadLocal threadSpec = new ThreadLocal();

    static void setParameter(String parameterName, Object parameter) {
        SecurityManager securityManager = System.getSecurityManager();
        if (parameterName.equals("threadLocalEcImplicitlyCa")) {
            ECParameterSpec curveSpec;
            if (securityManager != null) {
                securityManager.checkPermission(BC_EC_LOCAL_PERMISSION);
            }
            if ((parameter instanceof ECParameterSpec) || parameter == null) {
                curveSpec = (ECParameterSpec) parameter;
            } else {
                curveSpec = EC5Util.convertSpec((java.security.spec.ECParameterSpec) parameter, false);
            }
            if (curveSpec == null) {
                threadSpec.remove();
            } else {
                threadSpec.set(curveSpec);
            }
        } else if (parameterName.equals("ecImplicitlyCa")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_EC_PERMISSION);
            }
            if ((parameter instanceof ECParameterSpec) || parameter == null) {
                ecImplicitCaParams = (ECParameterSpec) parameter;
            } else {
                ecImplicitCaParams = EC5Util.convertSpec((java.security.spec.ECParameterSpec) parameter, false);
            }
        }
    }

    public static ECParameterSpec getEcImplicitlyCa() {
        ECParameterSpec spec = (ECParameterSpec) threadSpec.get();
        return spec != null ? spec : ecImplicitCaParams;
    }

    static int getReadLimit(InputStream in) throws IOException {
        if (in instanceof ByteArrayInputStream) {
            return in.available();
        }
        if (MAX_MEMORY > 2147483647L) {
            return Integer.MAX_VALUE;
        }
        return (int) MAX_MEMORY;
    }
}
