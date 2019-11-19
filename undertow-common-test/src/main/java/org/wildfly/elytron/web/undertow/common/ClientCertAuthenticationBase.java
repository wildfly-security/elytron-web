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
package org.wildfly.elytron.web.undertow.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;


/**
 * Test case for CLIENT_CERT authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class ClientCertAuthenticationBase extends AbstractHttpServerMechanismTest {

    protected ClientCertAuthenticationBase() throws Exception {
    }

    private SecurityRealm securityRealm;

    @Rule
    public UndertowServer serverA = createUndertowServerA();

    @Rule
    public UndertowServer serverB = createUndertowServerB();

    private AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();

        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverA.createUri())), "ladybird");
    }

    @Test
    public void testClientCertAfterSession() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.createUri())), "ladybird");
    }

    @Test
    public void testSSLSessionIdentityCacheHit() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create()
                .disableConnectionState() // Was causing premature connection closure and SSL session invalidation.
                .setSSLContext(createRecognizedSSLContext())
                .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                .build();

        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverA.createUri())), "ladybird");
        assertEquals(2, this.realmIdentityInvocationCount.get());

        for (int i = 0; i < 10; i++) {
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverA.createUri())), "ladybird");
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
        assertEquals(HttpStatus.SC_FORBIDDEN, httpClient.execute(new HttpGet(serverA.createUri())).getStatusLine().getStatusCode());
    }

    @Override
    protected String getMechanismName() {
        return "CLIENT_CERT";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        KeyStoreBackedSecurityRealm delegate = new KeyStoreBackedSecurityRealm(loadKeyStore("/tls/beetles.keystore"));

        this.securityRealm = new SecurityRealm() {
            @Override
            public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
                realmIdentityInvocationCount.incrementAndGet();
                return delegate.getRealmIdentity(principal);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
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
                .setPreRealmRewriter((String s) -> s.toLowerCase())
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
     * @param keystorePath the path to the key store to load.
     * @return the initialised key manager.
     */
    protected X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
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
    protected X509TrustManager getCATrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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
        try (InputStream keyStoreStream = ClientCertAuthenticationBase.class.getResourceAsStream(path)) {
            assertNotNull("InputStream must not be null", keyStoreStream);
            keyStore.load(keyStoreStream, "Elytron".toCharArray());
        }

        return keyStore;
    }

    protected SSLContext getSSLContext(final boolean authenticate) throws GeneralSecurityException, Exception {
        SSLContextBuilder builder = new SSLContextBuilder()
                .setSecurityDomain(getSecurityDomain())
                .setKeyManager(getKeyManager("/tls/scarab.keystore"))
                .setTrustManager(getCATrustManager());

        if (authenticate) {
            builder.setWantClientAuth(true);
        }

        return builder.build().create();
    }

    protected abstract UndertowServer createUndertowServerA() throws Exception;

    protected abstract UndertowServer createUndertowServerB() throws Exception;

}
