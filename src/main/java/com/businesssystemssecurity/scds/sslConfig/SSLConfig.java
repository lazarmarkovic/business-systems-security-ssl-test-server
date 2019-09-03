package com.businesssystemssecurity.scds.sslConfig;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

@Configuration()
public class SSLConfig {


    /**
     * Application keystore path.
     */
    @Value("${server.ssl.key-store}")
    private Resource keystore;

    /**
     * Application keystore type.
     */
    @Value("${server.ssl.key-store-type}")
    private String keystoreType;

    /**
     * Application keystore password.
     */
    @Value("${server.ssl.key-store-password}")
    private String keystorePassword;

    /**
     * Keystore alias for application client credential.
     */
    @Value("${server.ssl.key-alias}")
    private String applicationKeyAlias;

    /**
     * Application truststore path.
     */
    @Value("${server.ssl.trust-store}")
    private Resource truststore;

    /**
     * Application truststore type.
     */
    @Value("${server.ssl.trust-store-type}")
    private String truststoreType;

    /**
     * Application truststore password.
     */
    @Value("${server.ssl.trust-store-password}")
    private String truststorePassword;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(
                httpClient(keystoreType, keystore, keystorePassword, applicationKeyAlias,
                        truststoreType, truststore, truststorePassword)));
    }


    @Bean
    public HttpClient httpClient(String keystoreType, Resource keystore, String keystorePassword, String alias,
                                 String truststoreType, Resource truststore, String truststorePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            keyStore.load(keystore.getInputStream(), keystorePassword.toCharArray());

            KeyStore trustStore = KeyStore.getInstance(truststoreType);
            trustStore.load(truststore.getInputStream(), truststorePassword.toCharArray());

            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(trustStore, null)
                    .loadKeyMaterial(keyStore, keystorePassword.toCharArray(), (aliases, socket) -> alias)
                    .build();

            SSLConnectionSocketFactory sslFactory = new SSLConnectionSocketFactory(sslcontext,
                    new String[]{"TLSv1.2"},
                    null, SSLConnectionSocketFactory.getDefaultHostnameVerifier());

            return HttpClients.custom().setSSLSocketFactory(sslFactory).build();
        } catch (Exception e) {
            throw new IllegalStateException("Error while configuring SSL rest template", e);
        }
    }
}