/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.elytron.web.undertow.server;

import static org.junit.Assert.assertEquals;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.server.util.UndertowServer;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.x500.X500AttributePrincipalDecoder;


/**
 * Test case for CLIENT_CERT authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ClientCertAuthenticationTest extends AbstractHttpServerMechanismTest {

    private SecurityRealm securityRealm;

    @Rule
    public UndertowServer serverConfigurationA = new UndertowServer(createRootHttpHandler(), () -> {
        try {
            return new SSLContextBuilder()
                    .setSecurityDomain(getSecurityDomain())
                    .setKeyManager(getKeyManager("/tls/scarab.keystore"))
                    .setTrustManager(getCATrustManager())
                    .build().create();
        } catch (Exception cause) {
            throw new RuntimeException("Could not create server ssl context.", cause);
        }
    });

    @Rule
    public UndertowServer serverConfigurationB = new UndertowServer(createRootHttpHandler(), 7777, () -> {
        try {
            return new SSLContextBuilder()
                .setKeyManager(getKeyManager("/tls/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setWantClientAuth(true)
                .build().create();
        } catch (Exception cause) {
            throw new RuntimeException("Could not create server ssl context.", cause);
        }
    });

    private AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();

        assertSuccessfulResponse(httpClient.execute(new HttpGet(new URI("https", null, "localhost", 7776, null, null, null))), "ladybird");
    }

    @Test
    public void testClientCertAfterSession() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();
        assertSuccessfulResponse(httpClient.execute(new HttpGet(new URI("https", null, "localhost", 7777, null, null, null))), "ladybird");
    }

    @Test
    public void testSSLSessionIdentityCacheHit() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();

        assertSuccessfulResponse(httpClient.execute(new HttpGet(new URI("https", null, "localhost", 7776, null, null, null))), "ladybird");

        for (int i = 0; i < 10; i++) {
            assertSuccessfulResponse(httpClient.execute(new HttpGet(new URI("https", null, "localhost", 7776, null, null, null))), "ladybird");
        }

        // two hits during the first interaction, after that we should expect no more hits to the realm
        assertEquals(2, this.realmIdentityInvocationCount.get());
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createUnrecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();
        assertEquals(HttpStatus.SC_FORBIDDEN, httpClient.execute(new HttpGet(new URI("https", null, "localhost", 7776, null, null, null))).getStatusLine().getStatusCode());
    }

    @Override
    protected String getMechanismName() {
        return "CLIENT-CERT";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        KeyStoreBackedSecurityRealm delegate = new KeyStoreBackedSecurityRealm(loadKeyStore("/tls/beetles.keystore"));

        this.securityRealm = new SecurityRealm() {
            @Override
            public RealmIdentity getRealmIdentity(IdentityLocator locator) throws RealmUnavailableException {
                realmIdentityInvocationCount.incrementAndGet();
                return delegate.getRealmIdentity(locator);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return delegate.getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        };

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(PrincipalDecoder.aggregate(new X500AttributePrincipalDecoder("2.5.4.3", 1), PrincipalDecoder.DEFAULT))
                .setPreRealmRewriter(s -> s.toLowerCase())
                .setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));


        return builder.build();
    }

    private SSLContext createRecognizedSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(new KeyManager[] {getKeyManager("/tls/ladybird.keystore")}, new TrustManager[] { getCATrustManager() }, null);

        return sslContext;
    }

    private SSLContext createUnrecognizedSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(new KeyManager[] {getKeyManager("/tls/tiger.keystore")}, new TrustManager[] { getCATrustManager() }, null);

        return sslContext;
    }

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystoreName the name of the key store to load.
     * @return the initialised key manager.
     */
    private X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(loadKeyStore(keystorePath), "Elytron".toCharArray());

        for (KeyManager current : keyManagerFactory.getKeyManagers()) {
            if (current instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509ExtendedKeyManager.");
    }

    /**
     * Get the trust manager that trusts all certificates signed by the certificate authority.
     *
     * @return the trust manager that trusts all certificates signed by the certificate authority.
     * @throws KeyStoreException
     */
    private X509TrustManager getCATrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(loadKeyStore("/tls/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream caTrustStoreFile = ClientCertAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, "Elytron".toCharArray());
        }

        return keyStore;
    }
}
