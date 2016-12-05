/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import io.undertow.server.session.InMemorySessionManager;
import io.undertow.server.session.SessionManager;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.server.util.UndertowServer;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionFactory;
import org.wildfly.security.http.util.sso.SingleSignOnServerMechanismFactory;
import org.wildfly.security.http.util.sso.SingleSignOnSessionFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Ignore("https://github.com/wildfly-security/elytron-web/issues/45")
public class FormAuthenticationWithClusteredSSOTest extends AbstractHttpServerMechanismTest {

    private Map<Integer, SessionManager> sessionManagers = new HashMap<>();

    @Rule
    public UndertowServer serverA = new UndertowServer(createRootHttpHandler(createSessionManager(7776)), 7776);

    @Rule
    public UndertowServer serverB = new UndertowServer(createRootHttpHandler(createSessionManager(7777)), 7777);

    @Rule
    public UndertowServer serverC = new UndertowServer(createRootHttpHandler(createSessionManager(7778)), 7778);

    @Rule
    public UndertowServer serverD = new UndertowServer(createRootHttpHandler(createSessionManager(7779)), 7779);
    @Rule
    public UndertowServer serverE = new UndertowServer(createRootHttpHandler(createSessionManager(7780)), 7780);

    @Test
    public void testSingleSignOn() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));

        assertFalse(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());

        // authenticate on NODE_A
        HttpPost httpAuthenticate = new HttpPost(serverA.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse execute = httpClient.execute(httpAuthenticate);

        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverD.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverE.getServerUri())), "ladybird");
    }

    @Test
    public void testSingleLogout() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));

        // authenticate on NODE_A
        HttpPost httpAuthenticate = new HttpPost(serverA.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse execute = httpClient.execute(httpAuthenticate);

        assertSuccessfulResponse(execute, "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverD.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverE.getServerUri())), "ladybird");

        httpClient.execute(new HttpGet(serverB.getServerUri().toString() + "/logout"));

        assertLoginPage(httpClient.execute(new HttpGet(serverC.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverB.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverD.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverE.getServerUri())));
    }

    @Test
    public void testSingleLogoutWhenNodeIsFailing() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));

        // authenticate on NODE_A
        HttpPost httpAuthenticate = new HttpPost(serverA.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse execute = httpClient.execute(httpAuthenticate);

        assertSuccessfulResponse(execute, "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverD.getServerUri())), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverE.getServerUri())), "ladybird");

        serverC.forceShutdown();
        serverE.forceShutdown();

        httpClient.execute(new HttpGet(serverB.getServerUri().toString() + "/logout"));

        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverB.getServerUri())));
        assertLoginPage(httpClient.execute(new HttpGet(serverD.getServerUri())));
    }

    @Test
    public void testSessionInvalidation() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));

        for (int i = 0; i < 10; i++) {
            HttpPost httpAuthenticate = new HttpPost(serverA.getServerUri().toString() + "/j_security_check");
            List parameters = new ArrayList();

            parameters.add(new BasicNameValuePair("j_username", "ladybird"));
            parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

            httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

            HttpResponse execute = httpClient.execute(httpAuthenticate);

            assertSuccessfulResponse(execute, "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverA.getServerUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.getServerUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.getServerUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverD.getServerUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverE.getServerUri())), "ladybird");

            httpClient.execute(new HttpGet(serverA.getServerUri().toString() + "/logout"));

            assertLoginPage(httpClient.execute(new HttpGet(serverC.getServerUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverA.getServerUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverB.getServerUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverD.getServerUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverE.getServerUri())));
        }

        assertEquals(1, sessionManagers.get(7776).getActiveSessions().size());
        assertEquals(1, sessionManagers.get(7777).getActiveSessions().size());
        assertEquals(1, sessionManagers.get(7778).getActiveSessions().size());
        assertEquals(1, sessionManagers.get(7779).getActiveSessions().size());
        assertEquals(1, sessionManagers.get(7780).getActiveSessions().size());
    }

    @Override
    protected String getMechanismName() {
        return "FORM";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();

        passwordMap.put("ladybird", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));

        SimpleMapBackedSecurityRealm securityRealm = new SimpleMapBackedSecurityRealm();

        securityRealm.setPasswordMap(passwordMap);

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", securityRealm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));

        return builder.build();
    }

    @Override
    protected HttpServerAuthenticationMechanismFactory doCreateHttpServerMechanismFactory(HashMap properties) {
        HttpServerAuthenticationMechanismFactory delegate = super.doCreateHttpServerMechanismFactory(properties);

        KeyStore keyStore;

        try {
            keyStore = loadKeyStore("/tls/server.keystore");
        } catch (Exception cause) {
            throw new RuntimeException("Failed to load server key store.", cause);
        }

        String cacheManagerName = UUID.randomUUID().toString();
        EmbeddedCacheManager cacheManager = new DefaultCacheManager(
                GlobalConfigurationBuilder.defaultClusteredBuilder()
                        .globalJmxStatistics().cacheManagerName(cacheManagerName)
                        .transport().nodeName(cacheManagerName).clusterName("default-cluster")
                        .build(),
                new ConfigurationBuilder()
                        .clustering()
                        .cacheMode(CacheMode.REPL_SYNC)
                        .build()
        );

        Cache<String, Object> sessions = cacheManager.getCache();

        SingleSignOnServerMechanismFactory.SingleSignOnConfiguration signOnConfiguration = new SingleSignOnServerMechanismFactory.SingleSignOnConfiguration("JSESSIONSSOID", null, null, false, false);
        SingleSignOnSessionFactory singleSignOnSessionFactory = new DefaultSingleSignOnSessionFactory(sessions, keyStore, "server", "password", null);

        return new SingleSignOnServerMechanismFactory(delegate, singleSignOnSessionFactory, signOnConfiguration);
    }

    private  SessionManager createSessionManager(int port) {
        InMemorySessionManager sessionManager = new InMemorySessionManager("" + port);

        sessionManagers.put(port, sessionManager);

        return sessionManager;
    }

    private KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream caTrustStoreFile = ClientCertAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, "password".toCharArray());
        }

        return keyStore;
    }
}
