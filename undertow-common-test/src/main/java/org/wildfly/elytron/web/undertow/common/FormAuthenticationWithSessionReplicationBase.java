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

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Ignore("https://github.com/wildfly-security/elytron-web/issues/45")
public abstract class FormAuthenticationWithSessionReplicationBase extends AbstractHttpServerMechanismTest {

    @Rule
    public UndertowServer serverA = createUndertowServer(7776);

    @Rule
    public UndertowServer serverB = createUndertowServer(7777);

    @Rule
    public UndertowServer serverC = createUndertowServer(7778);

    protected FormAuthenticationWithSessionReplicationBase() throws Exception {
    }

    @Test
    public void testSuccessFulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.createUri())));

        HttpPost httpAuthenticate = new HttpPost(serverA.createUri("/j_security_check"));
        List<NameValuePair> parameters = new ArrayList<>();

        parameters.add(new BasicNameValuePair("j_username", "ladybird"));
        parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse execute = httpClient.execute(httpAuthenticate);

        for (int i = 0; i < 2; i++) {
            assertSuccessfulResponse(execute, "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.createUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.createUri())), "ladybird");
        }
    }

    @Test
    public void testSessionInvalidation() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();

        assertLoginPage(httpClient.execute(new HttpGet(serverA.createUri())));

        for (int i = 0; i < 10; i++) {
            HttpPost httpAuthenticate = new HttpPost(serverA.createUri("/j_security_check"));
            List<NameValuePair> parameters = new ArrayList<>();

            parameters.add(new BasicNameValuePair("j_username", "ladybird"));
            parameters.add(new BasicNameValuePair("j_password", "Coleoptera"));

            httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

            HttpResponse execute = httpClient.execute(httpAuthenticate);

            assertSuccessfulResponse(execute, "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverA.createUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverB.createUri())), "ladybird");
            assertSuccessfulResponse(httpClient.execute(new HttpGet(serverC.createUri())), "ladybird");

            httpClient.execute(new HttpGet(serverA.createUri("/logout")));

            assertLoginPage(httpClient.execute(new HttpGet(serverC.createUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverA.createUri())));
            assertLoginPage(httpClient.execute(new HttpGet(serverB.createUri())));
        }
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

    protected abstract UndertowServer createUndertowServer(int port) throws Exception;

}
