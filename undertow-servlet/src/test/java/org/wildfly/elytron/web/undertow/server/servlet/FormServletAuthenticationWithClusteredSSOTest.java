/*
 * Copyright 2024 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.elytron.web.undertow.server.servlet;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.infinispan.Cache;
import org.infinispan.commons.configuration.ClassAllowList;
import org.infinispan.commons.marshall.JavaSerializationMarshaller;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.common.AbstractHttpServerMechanismTest;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.servlet.util.UndertowServletServer;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnManager;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionIdentifierFactory;
import org.wildfly.security.http.util.sso.SingleSignOnEntry;
import org.wildfly.security.http.util.sso.SingleSignOnManager;
import org.wildfly.security.http.util.sso.SingleSignOnServerMechanismFactory;
import org.wildfly.security.http.util.sso.SingleSignOnSessionFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@Ignore
public class FormServletAuthenticationWithClusteredSSOTest extends AbstractHttpServerMechanismTest {

    private Supplier<KeyPair> keyPairSupplier;
    private AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Rule
    public final UndertowServer serverA = createUndertowServer(7776);

    @Rule
    public final UndertowServer serverB = createUndertowServer(7777);

    public FormServletAuthenticationWithClusteredSSOTest() throws Exception {
    }

    @Override
    protected String getMechanismName() {
        return "FORM";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();

        passwordMap.put("ladybird",
                new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));

        SimpleMapBackedSecurityRealm delegate = new SimpleMapBackedSecurityRealm();

        delegate.setPasswordMap(passwordMap);

        SecurityRealm securityRealm = new SecurityRealm() {

            @Override
            public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
                realmIdentityInvocationCount.incrementAndGet();
                return delegate.getRealmIdentity(principal);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                                                            AlgorithmParameterSpec algorithmParameterSpec) throws RealmUnavailableException {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName, algorithmParameterSpec);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType,
                                                         String algorithmName) throws RealmUnavailableException {
                return delegate.getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        };

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", securityRealm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));

        return builder.build();
    }

    private UndertowServer createUndertowServer(int port) throws Exception {
        return UndertowServletServer.builder()
                .setAuthenticationMechanism(getMechanismName())
                .setSecurityDomain(getSecurityDomain())
                .setPort(port)
                .setContextRoot("/" + port)
                .setDeploymentName(String.valueOf(port))
                .setHttpServerAuthenticationMechanismFactory(getHttpServerAuthenticationMechanismFactory(Collections.emptyMap()))
                .build();
    }

    @Override
    protected HttpServerAuthenticationMechanismFactory getHttpServerAuthenticationMechanismFactory(Map<String, ?> properties) {
        HttpServerAuthenticationMechanismFactory delegate = super.getHttpServerAuthenticationMechanismFactory(properties);

        String cacheManagerName = UUID.randomUUID().toString();
        ClassAllowList allowList = new ClassAllowList();
        allowList.addRegexps(".*");

        EmbeddedCacheManager cacheManager = new DefaultCacheManager(
                GlobalConfigurationBuilder.defaultClusteredBuilder()
                        .globalJmxStatistics().cacheManagerName(cacheManagerName).defaultCacheName("Default")
                        .transport().nodeName(cacheManagerName).addProperty(JGroupsTransport.CONFIGURATION_FILE, "fast.xml")
                        .serialization().marshaller(new JavaSerializationMarshaller(allowList))
                        .build(),
                new ConfigurationBuilder()
                        .clustering()
                        .cacheMode(CacheMode.REPL_SYNC)
                        .build()
        );

        Cache<String, SingleSignOnEntry> cache = cacheManager.getCache();
        SingleSignOnManager manager = new DefaultSingleSignOnManager(cache, new DefaultSingleSignOnSessionIdentifierFactory(), (id, entry) -> cache.put(id, entry));
        SingleSignOnServerMechanismFactory.SingleSignOnConfiguration signOnConfiguration =
                new SingleSignOnServerMechanismFactory.SingleSignOnConfiguration("JSESSIONSSOID", null,
                        "/", false, false);

        if (keyPairSupplier == null) {
            keyPairSupplier = new KeyPairSupplier();
        }
        SingleSignOnSessionFactory singleSignOnSessionFactory = new DefaultSingleSignOnSessionFactory(manager, keyPairSupplier.get());

        return new SingleSignOnServerMechanismFactory(delegate, singleSignOnSessionFactory, signOnConfiguration);
    }

    @Test
    public void testSingleSignOnAcrossTwoAppsWithLogout() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.createUri())));

        assertFalse(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());

        // log into APP_A
        HttpResponse execute = loginToApp(httpClient, serverA, "ladybird", "Coleoptera");
        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "ladybird");
        String appOneSessionId = getSessionIdForApp(cookieStore, serverA);

        // can now access APP_B without logging in again
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.createUri())), "ladybird");
        String appTwoSessionId = getSessionIdForApp(cookieStore, serverB);

        // log out of APP_A
        httpClient.execute(new HttpGet(serverA.createUri("/logout")));

        // log into APP_A again
        execute = loginToApp(httpClient, serverA, "ladybird", "Coleoptera");
        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "ladybird");
        String appOneNewSessionId = getSessionIdForApp(cookieStore, serverA);

        // the session ID for APP_A should now be different from the initial session ID
        assertTrue(appOneSessionId != null && appOneNewSessionId != null && ! appOneSessionId.equals(appOneNewSessionId));

        // access APP_B without logging in again
        assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.createUri())), "ladybird");
        String appTwoNewSessionId = getSessionIdForApp(cookieStore, serverB);

        // the session ID for APP_B should now be different from the initial session ID
        assertTrue(appTwoSessionId != null && appTwoNewSessionId != null && ! appTwoSessionId.equals(appTwoNewSessionId));
    }

    private static HttpResponse loginToApp(HttpClient httpClient, UndertowServer server, String username, String password) throws Exception {
        assertLoginPage(httpClient.execute(new HttpGet(server.createUri())));
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>(2);
        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));
        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));
        return httpClient.execute(httpAuthenticate);
    }

    private static String getSessionIdForApp(BasicCookieStore cookieStore, UndertowServer server) {
        return cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONID")
                && cookie.getPath().equals(server.getContextRoot())).findAny().get().getValue();
    }

    class KeyPairSupplier implements Supplier<KeyPair> {

        private final KeyPair keyPair;

        KeyPairSupplier() {
            try {
                this.keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException();
            }
        }

        @Override
        public KeyPair get() {
            return this.keyPair;
        }
    }

}
