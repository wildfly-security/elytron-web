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

import static io.undertow.util.Headers.AUTHORIZATION;
import static io.undertow.util.Headers.BASIC;
import static io.undertow.util.Headers.WWW_AUTHENTICATE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import io.undertow.util.FlexBase64;
import io.undertow.util.StatusCodes;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.server.util.UndertowServer;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Test case to test HTTP BASIC authentication where authentication is backed by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BasicAuthenticationTest extends AbstractHttpServerMechanismTest {

    @Rule
    public UndertowServer server = new UndertowServer(createRootHttpHandler());

    @Test
    public void testUnauthorized() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.getServerUri());

        assertUnauthorizedResponse(httpClient.execute(get));
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.getServerUri());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + FlexBase64.encodeString("elytron:Coleoptera".getBytes(), false));

        HttpResponse result = httpClient.execute(get);

        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());
        assertSuccessfulResponse(result, "elytron");
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.getServerUri());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + FlexBase64.encodeString("elytron:bad_password".getBytes(), false));

        assertUnauthorizedResponse(httpClient.execute(get));
    }

    private void assertUnauthorizedResponse(HttpResponse result) {
        assertEquals(StatusCodes.UNAUTHORIZED, result.getStatusLine().getStatusCode());

        Header wwwAuthenticateHeader = result.getFirstHeader(WWW_AUTHENTICATE.toString());

        assertNotNull(wwwAuthenticateHeader);
        assertEquals(BASIC + " realm=\"Elytron Realm\"", wwwAuthenticateHeader.getValue());
    }

    @Override
    protected String getMechanismName() {
        return "BASIC";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);

        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();
        passwordMap.put("elytron", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));

        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm();
        simpleRealm.setPasswordMap(passwordMap);

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", simpleRealm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));

        return builder.build();
    }
}
