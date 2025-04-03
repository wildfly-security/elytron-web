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
package org.wildfly.elytron.web.undertow.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.net.URI;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.barehttp.BareHttpClient;
import org.wildfly.elytron.web.barehttp.BareHttpRequest;
import org.wildfly.elytron.web.barehttp.BareHttpResponse;
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
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class FormAuthenticationBase extends AbstractHttpServerMechanismTest {

    protected FormAuthenticationBase() throws Exception {
    }

    @Rule
    public UndertowServer server = createUndertowServer();

    private AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Test
    public void testRedirectLoginPage() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();

        assertLoginPage(httpClient.execute(new HttpGet(server.createUri())));
    }

    @Test
    public void testFormSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()).build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
    }

    @Test
    public void testSessionIdentityCache() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()).build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");

        for (int i = 0; i < 10; i++) {
            assertSuccessfulResponse(httpClient.execute(new HttpGet(server.createUri())), "ladybird");
        }

        assertEquals(1, realmIdentityInvocationCount.get());
    }

    @Test
    public void testLogout() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()).build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(server.createUri())), "ladybird");

        httpClient.execute(new HttpGet(server.createUri("/logout")));

        assertLoginPage(httpClient.execute(new HttpGet(server.createUri())));
    }

    private static final String J_SECURITY_DATA = "j_username=%s&j_password=%s";

    /**
     * Common method for tests using the {@code BareHttpClient} implementation.
     * @param initialPath
     * @param redirectVerifier
     * @throws Exception
     */
    public void bareHttpClientRunner(final String initialPath, Predicate<String> redirectVerifier) throws Exception {
        URI defaultUri = server.createUri();

        BareHttpClient httpClient = BareHttpClient.builder().build();

        final String hostName = defaultUri.getHost();
        final int port = defaultUri.getPort();

        BareHttpClient.Target targetServer = httpClient.target(hostName, port);

        BareHttpRequest initialRequest = targetServer.buildRequest(initialPath).build();
        BareHttpResponse httpResponse = initialRequest.execute();
        assertNotEquals("Request Rejected", 400, httpResponse.getStatusCode());

        assertTrue("Response should set JSESSIONID", targetServer.hasCookie("JSESSIONID"));
        if (httpResponse.getStatusCode() == 302) {
            // Now get the location we were redirected to before processing to check the login page.
            String location = httpResponse.getHeaders().get("Location").get(0);
            URI locationUri = new URI(location);

            assertEquals("Expected same hostName on redirect", hostName, locationUri.getHost());
            assertEquals("Expected same port on redirect", port, locationUri.getPort());

            httpResponse = targetServer.buildRequest(locationUri.getPath())
                    .build().execute();
        }
        // This first request should have resulted in the login page being returned.
        // The end result should be a HTTP 200 status code.
        assertEquals("Expected Success", 200, httpResponse.getStatusCode());
        assertTrue("We expect the login page.", httpResponse.getMessageBody().contains("Login Page"));

        URI jSecurityCheckUri = server.createUri("/j_security_check");
        String messageBody = String.format(J_SECURITY_DATA, "ladybird", "Coleoptera");

        httpResponse = targetServer.buildRequest(jSecurityCheckUri.getPath())
                .setMessageBody(messageBody)
                .build()
                .execute();

        assertEquals("Expected Redirect", 302, httpResponse.getStatusCode());
        String location = httpResponse.getHeaders().get("Location").get(0);

        String redirectPath =  location.substring(location.indexOf('/', 7));

        assertTrue("Redirect URI", redirectVerifier.test(redirectPath));

        URI locationUri = new URI(location);
        assertEquals("Expected same hostName on redirect", hostName, locationUri.getHost());
        assertEquals("Expected same port on redirect", port, locationUri.getPort());

        httpResponse = targetServer.buildRequest(redirectPath)
                .build().execute();

        assertEquals("Expected Success", 200, httpResponse.getStatusCode());
        assertEquals("Expected UndertowUser", "ladybird", httpResponse.getHeaders().get("UndertowUser").get(0));
        assertEquals("Expected ElytronUser", "ladybird", httpResponse.getHeaders().get("ElytronUser").get(0));
    }

    @Test
    public void testDefaultURLBare() throws Exception {
        URI defaultUri = server.createUri();
        String defaultPath = defaultUri.getPath().isEmpty() ? "/" : defaultUri.getPath();

        bareHttpClientRunner(defaultUri.getPath(), (p) ->  defaultPath.equals(p));
    }

    @Test
    public void testEncodedQueryStringBare() throws Exception {
        String encodedQuery = "project=%7BElytron%20Web%7D";
        URI defaultUri = server.createUri();
        String defaultPath = defaultUri.getPath().isEmpty() ? "/" : defaultUri.getPath();

        String path = defaultPath + "?" + encodedQuery;

        bareHttpClientRunner(path, (p) -> path.equals(p));
    }

    @Test
    public void testNonEncodedQueryStringBare() throws Exception {
        String nonEncodedQuery = "project={ElytronWeb}";
        URI defaultUri = server.createUri();
        String defaultPath = defaultUri.getPath().isEmpty() ? "/" : defaultUri.getPath();

        String path = defaultPath + "?" + nonEncodedQuery;

        String encodedQuery = "project=%7BElytron%20Web%7D";
        String expectedPath = defaultPath + "?" + encodedQuery;

        bareHttpClientRunner(path, (p) -> expectedPath.equals(p));
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

        SimpleMapBackedSecurityRealm delegate = new SimpleMapBackedSecurityRealm();

        delegate.setPasswordMap(passwordMap);

        SecurityRealm securityRealm = new SecurityRealm() {

            @Override
            public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
                realmIdentityInvocationCount.incrementAndGet();
                return delegate.getRealmIdentity(principal);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec algorithmParameterSpec) throws RealmUnavailableException {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName, algorithmParameterSpec);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return delegate.getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        };

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", securityRealm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));

        return builder.build();
    }

    protected abstract UndertowServer createUndertowServer() throws Exception;
}
