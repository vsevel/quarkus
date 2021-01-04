package io.quarkus.vault.runtime;

import io.quarkus.vault.runtime.config.VaultRuntimeConfig;

public interface VaultConfigHolder {
    VaultRuntimeConfig getVaultRuntimeConfig();
}
