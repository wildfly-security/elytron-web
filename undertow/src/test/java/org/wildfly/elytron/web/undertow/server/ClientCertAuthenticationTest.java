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
import static org.junit.Assert.assertTrue;
import static org.wildfly.elytron.web.undertow.server.DefaultServer.getAcceptListener;
import static org.wildfly.elytron.web.undertow.server.DefaultServer.getXnioWorker;
import static org.wildfly.security.auth.server.HttpAuthenticationFactory.getHostName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismInformation;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.x500.X500AttributePrincipalDecoder;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.StreamConnection;
import org.xnio.channels.AcceptingChannel;

import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.util.StatusCodes;


/**
 * Test case for CLIENT_CERT authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(DefaultServer.class)
public class ClientCertAuthenticationTest {

    private static SSLContext clientContext;

    private static SecurityDomain securityDomain;

    private static HttpAuthenticationFactory httpAuthenticationFactory;

    @BeforeClass
    public static void setupHttpAuthenticationFactory() throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/tls/beetles.keystore"));

        securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                    .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(PrincipalDecoder.aggregate(new X500AttributePrincipalDecoder("2.5.4.3", 1), PrincipalDecoder.DEFAULT))
                .setPreRealmRewriter(s -> s.toLowerCase())
                .setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()))
                .build();

        HttpServerAuthenticationMechanismFactory factory = new ServerMechanismFactoryImpl();
        httpAuthenticationFactory = HttpAuthenticationFactory.builder()
            .setSecurityDomain(securityDomain)
            .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                    MechanismConfiguration.builder()
                    .build()))
            .setFactory(factory)
            .build();
    }

    @BeforeClass
    public static void setupClient() throws Exception {
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(new KeyManager[] { getKeyManager("/tls/ladybird.keystore") },
                new TrustManager[] { getCATrustManager() }, null);

        ClientCertAuthenticationTest.clientContext = clientContext;
    }

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystoreName the name of the key store to load.
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
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
    private static X509TrustManager getCATrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(loadKeyStore("/tls/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private static KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream caTrustStoreFile = ClientCertAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, "Elytron".toCharArray());
        }

        return keyStore;
    }

    // Test Mechanism Is Available
    @Test
    public void testClientCertAuthenticationAvailable() {
        assertTrue("CLIENT_CERT Authentication Supported", httpAuthenticationFactory.getMechanismNames().contains("CLIENT_CERT"));
    }

    // Test authentication attached to SSLSession.
    @Test
    public void testClientCertFromSession() throws Exception {
        performClientCertTest(new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/tls/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .build().create());
    }

    // Test authentication delayed until mechanism.

    @Test
    public void testClientCertAfterSession() throws Exception{
        performClientCertTest(new SSLContextBuilder()
                .setKeyManager(getKeyManager("/tls/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setWantClientAuth(true)
                .build().create());
    }

    /*
     * Regardless of how the SSLContext is defined the end result should be the same, authentication during SSLSession
     * establishment is just an optimisation.
     */
    private void performClientCertTest(final SSLContext serverContext) throws Exception {
        UndertowXnioSsl ssl = new UndertowXnioSsl(getXnioWorker().getXnio(), OptionMap.EMPTY, serverContext);
        OptionMap serverOptions = OptionMap.builder()
                .set(Options.TCP_NODELAY, true)
                .set(Options.BACKLOG, 1000)
                .set(Options.REUSE_ADDRESSES, true)
                .set(Options.BALANCING_TOKENS, 1)
                .set(Options.BALANCING_CONNECTIONS, 2)
                .getMap();

        /*
         * Full Chain Set Up
         */
        HttpHandler nextHandler = new ResponseHandler(httpAuthenticationFactory.getSecurityDomain());
        nextHandler = new ElytronRunAsHandler(nextHandler);
        nextHandler = new BlockingHandler(nextHandler);
        nextHandler = new AuthenticationCallHandler(nextHandler);
        nextHandler = new AuthenticationConstraintHandler(nextHandler);
        nextHandler = ElytronContextAssociationHandler.builder()
                        .setNext(nextHandler)
                        .setMechanismSupplier(httpServerRequest -> getAuthenticationMechanisms(httpServerRequest))
                        .build();

        DefaultServer.setTestHandler(nextHandler);

        AcceptingChannel<? extends StreamConnection> server = ssl.createSslConnectionServer(getXnioWorker(), new InetSocketAddress("localhost", 7777), getAcceptListener(), serverOptions);
        try {
            server.getAcceptSetter().set(getAcceptListener());
            server.resumeAccepts();

            HttpClient httpClient = HttpClientBuilder.create()
                    .setSSLContext(clientContext)
                    .setSSLHostnameVerifier((String h, SSLSession s) -> true)
                    .build();
            HttpGet get = new HttpGet(new URI("https", null, "localhost", 7777, null, null, null));
            HttpResponse result = httpClient.execute(get);

            assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());

            Header[] values = result.getHeaders("ProcessedBy");
            assertEquals(1, values.length);
            assertEquals("ResponseHandler", values[0].getValue());

            values = result.getHeaders("UndertowUser");
            assertEquals(1, values.length);
            assertEquals("ladybird", values[0].getValue());

            values = result.getHeaders("ElytronUser");
            assertEquals(1, values.length);
            assertEquals("ladybird", values[0].getValue());

            readResponse(result);
        } finally {
            server.close();
        }
    }

    public static String readResponse(final HttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            return "";
        }
        return readResponse(entity.getContent());
    }

    public static String readResponse(InputStream stream) throws IOException {

        byte[] data = new byte[100];
        int read;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((read = stream.read(data)) != -1) {
            out.write(data, 0, read);
        }
        return new String(out.toByteArray(), Charset.forName("UTF-8"));
    }

    private static HttpServerAuthenticationMechanism createMechanism(final String mechanismName) {
        try {
            return httpAuthenticationFactory.createMechanism(mechanismName);
        } catch (HttpAuthenticationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static List<HttpServerAuthenticationMechanism> getAuthenticationMechanisms(final HttpServerRequest httpServerRequest) {
        final String hostName = getHostName(httpServerRequest);
        final String protocol = httpServerRequest.getRequestURI().getScheme();
        return httpAuthenticationFactory.getMechanismNames().stream()
                .map(s -> {
                    try {
                        // Now that we have the host name and protocol name, make sure the mechanism is actually available
                        MechanismInformation mechanismInformation = new MechanismInformation() {

                            @Override
                            public String getProtocol() {
                                return protocol;
                            }

                            @Override
                            public String getMechanismType() {
                                return "HTTP";
                            }

                            @Override
                            public String getMechanismName() {
                                return s;
                            }

                            @Override
                            public String getHostName() {
                                return hostName;
                            }
                        };
                        if (httpAuthenticationFactory.isMechAvailable(mechanismInformation)) {
                            return createMechanism(s);
                        } else {
                            return null;
                        }
                    } catch (Exception e) {
                        return null;
                    }
                })
                .filter(m -> m != null)
                .collect(Collectors.toList());
    }

}
