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
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import io.undertow.server.session.InMemorySessionManager;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.server.util.UndertowServer;
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
public class FormAuthenticationTest extends AbstractHttpServerMechanismTest {

    @Rule
    public UndertowServer server = new UndertowServer(createRootHttpHandler(new InMemorySessionManager("default-session-manager")));

    private AtomicInteger realmIdentityInvocationCount = new AtomicInteger(0);

    @Test
    public void testRedirectLoginPage() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();

        assertLoginPage(httpClient.execute(new HttpGet(server.getServerUri())));
    }

    @Test
    public void testFormSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
    }

    @Test
    public void testSessionIdentityCache() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");

        for (int i = 0; i < 10; i++) {
            assertSuccessfulResponse(httpClient.execute(new HttpGet(server.getServerUri())), "ladybird");
        }

        assertEquals(1, realmIdentityInvocationCount.get());
    }

    @Test
    public void testLogout() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.getServerUri().toString() + "/j_security_check");
        List parameters = new ArrayList();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
        assertSuccessfulResponse(httpClient.execute(new HttpGet(server.getServerUri())), "ladybird");

        httpClient.execute(new HttpGet(server.getServerUri().toString() + "/logout"));

        assertLoginPage(httpClient.execute(new HttpGet(server.getServerUri())));

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
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return delegate.getCredentialAcquireSupport(credentialType, algorithmName);
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
}
