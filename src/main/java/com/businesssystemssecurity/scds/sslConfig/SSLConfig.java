package com.businesssystemssecurity.scds.sslConfig;

import com.businesssystemssecurity.scds.GeneralException;
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

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
    private char[] keystorePassword;

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
    private char[] truststorePassword;


    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(
                httpClient(keystore, keystorePassword, truststore, truststorePassword)));
    }

    @Bean
    public HttpClient httpClient(Resource keystore, char[] keystorePassword,
                                 Resource truststore, char[] truststorePassword) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // Using null here initialises the TMF with the default trust store.
            tmf.init((KeyStore) null);

            /* Load trust store */
            KeyStore trustStore = KeyStore.getInstance(this.truststoreType);
            trustStore.load(truststore.getInputStream(), this.truststorePassword);


            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // Get hold of the default trust manager
            X509TrustManager x509TrustManager = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    x509TrustManager = (X509TrustManager) tm;
                    break;
                }
            }


            final X509TrustManager finalMyTm = x509TrustManager;
            X509TrustManager customTm = new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    if (finalMyTm != null) {
                        return finalMyTm.getAcceptedIssuers();
                    } else {
                        throw new GeneralException("Error. No trusted certificates.");
                    }
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain,
                                               String authType) throws CertificateException {

                    System.out.println("Checking server certificate trust.");

                    try {
                        if (finalMyTm != null) {
                            finalMyTm.checkServerTrusted(chain, authType);
                        } else {
                            throw new GeneralException("Error. No trusted certificates.");
                        }
                    } catch (CertificateException e) {
                        throw new CertificateException();
                    }

                    System.out.println("Done.");
                    System.out.println("Checking server certificate validity (OCSP).");

                    for (int i=0; i<chain.length; i++) {
                        System.out.println("CERT: " + chain[i].getSubjectDN().toString());
                    }

                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain,
                                               String authType) throws CertificateException {
                    // If you're planning to use client-cert auth,
                    // do the same as checking the server.

                    System.out.println("Checking client certificate trust.");
                    try {
                        if (finalMyTm != null) {
                            finalMyTm.checkClientTrusted(chain, authType);
                        } else {
                            throw new CertificateException();
                        }
                    } catch (CertificateException e) {
                        throw new CertificateException();
                    }

                    System.out.println("Done.");
                    System.out.println("Checking server certificate validity (OCSP).");

                    for (int i=0; i<chain.length; i++) {
                        System.out.println("CERT: " + chain[i].getSubjectDN().toString());
                    }
                }
            };

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance(this.keystoreType);
            keyStore.load(this.keystore.getInputStream(), this.keystorePassword);
            kmf.init(keyStore, this.keystorePassword);


//            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(trustStore, null)
//                    .loadKeyMaterial(keyStore, keystorePassword.toCharArray(), (aliases, socket) -> alias)
//                    .build();


            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), new TrustManager[] { customTm }, new SecureRandom());
            SSLConnectionSocketFactory sslFactory = new SSLConnectionSocketFactory(sslContext, new String[]{"TLSv1.2"},
                    null, SSLConnectionSocketFactory.getDefaultHostnameVerifier());

            return HttpClients.custom()
                    .setSSLSocketFactory(sslFactory)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Error while configuring SSL rest template", e);
        }
    }
}