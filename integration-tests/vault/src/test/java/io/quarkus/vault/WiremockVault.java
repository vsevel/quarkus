package io.quarkus.vault;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import java.util.Collections;
import java.util.Map;

import org.jboss.logging.Logger;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

public class WiremockVault implements QuarkusTestResourceLifecycleManager {

    private static final Logger LOG = Logger.getLogger(WiremockVault.class);

    private WireMockServer server;

    @Override
    public Map<String, String> start() {

        server = new WireMockServer(wireMockConfig().dynamicHttpsPort());
        server.start();
        LOG.info("wiremock vault server base url = " + server.baseUrl());

        server.stubFor(get(urlEqualTo("/v1/secret/foo"))
                .withHeader("X-Vault-Namespace", equalTo("accounting"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(
                                "{\"request_id\":\"bf5245f4-f194-2b13-80b7-6cad145b8135\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":2764800,\"wrap_info\":null,\"warnings\":null,\"auth\":null,"
                                        + "\"data\":{\"hello\":\"world\"}}")));

        return Collections.singletonMap("quarkus.vault.url", server.baseUrl());
    }

    @Override
    public int order() {
        return 1;
    }

    @Override
    public void stop() {
        if (server != null) {
            server.stop();
        }
    }
}
