/*
 * Copyright 2025 Red Hat, Inc.
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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.net.URI;
import java.net.URISyntaxException;
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
import org.junit.Test;
import org.wildfly.common.function.ExceptionFunction;
import org.wildfly.elytron.web.undertow.common.AbstractHttpServerMechanismTest;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.servlet.util.UndertowServletServer;
import org.wildfly.elytron.web.undertow.server.servlet.util.UndertowServletServer.Builder;
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
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Base class for the SSO testing.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class FormAuthenticationSSOBase extends AbstractHttpServerMechanismTest {

    protected Supplier<KeyPair> keyPairSupplier;
    protected AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Override
    protected String getMechanismName() {
        return "FORM";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();

        passwordMap.put("ladybird", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));
        passwordMap.put("dung", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleopterida".toCharArray()))))));

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

    protected Builder createUndertowServerBuilder(int port) throws Exception {
        return UndertowServletServer.builder()
            .setAuthenticationMechanism(getMechanismName())
            .setSecurityDomain(getSecurityDomain())
            .setPort(port)
            .setContextRoot("/" + port)
            .setDeploymentName(String.valueOf(port))
            .setHttpServerAuthenticationMechanismFactory(getHttpServerAuthenticationMechanismFactory(Collections.emptyMap()));
    }

    protected UndertowServer createUndertowServer(int port) throws Exception {
        return createUndertowServerBuilder(port).build();
    }

    protected abstract URI createUriAppA(final String alternativePath) throws URISyntaxException;
    protected abstract String getContextRootAppA();
    protected abstract URI createUriAppB(final String alternativePath) throws URISyntaxException;
    protected abstract String getContextRootAppB();

    @Test
    public void testSingleSignOnAcrossTwoAppsWithLogout() throws Exception {
        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClient httpClient = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();

        assertLoginPage(httpClient.execute(new HttpGet(createUriAppA(null))));

        assertFalse(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());

        // log into APP_A
        HttpResponse execute = loginToApp(httpClient, this::createUriAppA, "ladybird", "Coleoptera", false);
        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "ladybird");
        String appOneSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppA);
        assertNotNull(appOneSessionId);

        // can now access APP_B without logging in again
        assertSuccessfulResponse(httpClient.execute(new HttpGet(createUriAppB(null))), "ladybird");
        String appTwoSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppB);
        assertNotNull(appTwoSessionId);

        // log out of APP_A
        httpClient.execute(new HttpGet(createUriAppA("/logout")));

        // log into APP_A again
        execute = loginToApp(httpClient, this::createUriAppA, "ladybird", "Coleoptera", false);
        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "ladybird");
        String appOneNewSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppA);

        // the session ID for APP_A should now be different from the initial session ID
        assertNotNull(appOneNewSessionId);
        assertTrue(! appOneSessionId.equals(appOneNewSessionId));

        // access APP_B without logging in again
        assertSuccessfulResponse(httpClient.execute(new HttpGet(createUriAppB(null))), "ladybird");
        String appTwoNewSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppB);

        // the session ID for APP_B should now be different from the initial session ID
        assertNotNull(appTwoNewSessionId);
        assertTrue(! appTwoSessionId.equals(appTwoNewSessionId));

        // Now try re-authentication

        // log into APP_B as a new user
        execute = loginToApp(httpClient, this::createUriAppB, "dung", "Coleopterida", true);
        assertTrue(cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONSSOID")).findAny().isPresent());
        assertSuccessfulResponse(execute, "dung");
        String appTwoNewNewSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppB);

        // Verify that the session ID changed again.
        assertNotNull(appTwoNewNewSessionId);
        assertTrue(! appTwoNewNewSessionId.equals(appTwoNewSessionId));

        // Access App A without logging in again
        assertSuccessfulResponse(httpClient.execute(new HttpGet(createUriAppA(null))), "dung");
        String appOneNewNewSessionId = getSessionIdForApp(cookieStore, this::getContextRootAppB);

        // Verify the session ID change
        assertNotNull("App missing session ID", appOneNewNewSessionId);
        assertNotEquals("App session ID should have changed", appOneNewSessionId, appOneNewNewSessionId);
    }

    private static HttpResponse loginToApp(HttpClient httpClient, ExceptionFunction<String, URI, Exception> uri, String username, String password, boolean reAuth) throws Exception {
        if (! reAuth) {
            assertLoginPage(httpClient.execute(new HttpGet(uri.apply(null))));
        }
        HttpPost httpAuthenticate = new HttpPost(uri.apply("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>(2);
        parameters.add(new BasicNameValuePair("j_username", username));
        parameters.add(new BasicNameValuePair("j_password", password));
        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));
        return httpClient.execute(httpAuthenticate);
    }

    private static String getSessionIdForApp(BasicCookieStore cookieStore, Supplier<String> contextRoot) {
        return cookieStore.getCookies().stream().filter(cookie -> cookie.getName().equals("JSESSIONID")
                && cookie.getPath().equals(contextRoot.get())).findAny().get().getValue();
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
