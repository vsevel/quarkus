package io.quarkus.vault.runtime;

import java.util.Collections;
import java.util.function.Supplier;

import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.ConfigSourceProvider;
import org.jboss.logging.Logger;

import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.vault.runtime.config.VaultConfigSourceProvider;
import io.quarkus.vault.runtime.config.VaultRuntimeConfig;

@Recorder
public class VaultRecorder {

    private static final Logger log = Logger.getLogger(VaultRecorder.class);

    public RuntimeValue<ConfigSourceProvider> configureRuntimeProperties(VaultRuntimeConfig vaultRuntimeConfig) {
        if (vaultRuntimeConfig.url.isPresent()) {
            // Arc.container().instance(VaultAuthManager.class).get().setVaultRuntimeConfig(vaultRuntimeConfig);
            // Arc.container().instance(OkHttpVaultClient.class).get().initWith(vaultRuntimeConfig);
            return new RuntimeValue<>(new VaultConfigSourceProvider(vaultRuntimeConfig));
        } else {
            return emptyRuntimeValue();
        }
    }

    private RuntimeValue<ConfigSourceProvider> emptyRuntimeValue() {
        return new RuntimeValue<>(new EmptyConfigSourceProvider());
    }

    public Supplier<VaultConfigHolder> createVaultConfigHolder(VaultRuntimeConfig serverConfig) {
        return () -> () -> serverConfig;
    }

    private static class EmptyConfigSourceProvider implements ConfigSourceProvider {
        @Override
        public Iterable<ConfigSource> getConfigSources(ClassLoader forClassLoader) {
            return Collections.emptyList();
        }
    }
}
