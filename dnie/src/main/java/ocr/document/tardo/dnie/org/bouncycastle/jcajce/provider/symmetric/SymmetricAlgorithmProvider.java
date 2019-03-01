package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

abstract class SymmetricAlgorithmProvider extends AlgorithmProvider {
    SymmetricAlgorithmProvider() {
    }

    protected void addGMacAlgorithm(ConfigurableProvider configurableProvider, String str, String str2, String str3) {
        configurableProvider.addAlgorithm("Mac." + str + "-GMAC", str2);
        configurableProvider.addAlgorithm("Alg.Alias.Mac." + str + "GMAC", str + "-GMAC");
        configurableProvider.addAlgorithm("KeyGenerator." + str + "-GMAC", str3);
        configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + str + "GMAC", str + "-GMAC");
    }
}
