/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static io.undertow.util.Headers.AUTHORIZATION;
import static io.undertow.util.Headers.BASIC;
import static io.undertow.util.Headers.WWW_AUTHENTICATE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.util.FlexBase64;
import io.undertow.util.HttpString;
import io.undertow.util.StatusCodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.provider.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.provider.SimpleRealmEntry;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Test case to test HTTP BASIC authentication where authentication is backed by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(DefaultServer.class)
public class BasicAuthenticationTest extends TestBase {

    private static HttpAuthenticationFactory httpAuthenticationFactory;

    @BeforeClass
    public static void prepareSecurityConfiguration() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);

        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();
        passwordMap.put("elytron", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));

        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm();
        simpleRealm.setPasswordMap(passwordMap);

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", simpleRealm);
        SecurityDomain securityDomain = builder.build();

        HttpServerAuthenticationMechanismFactory factory = new ServerMechanismFactoryImpl();
        httpAuthenticationFactory = HttpAuthenticationFactory.builder()
            .setSecurityDomain(securityDomain)
            .addMechanism("BASIC",
                    MechanismConfiguration.builder()
                        .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                        .build()
                    )
            .setHttpServerAuthenticationMechanismFactory(factory)
            .build();
    }

    @Test
    public void testNoAuthentication() throws Exception {
        DefaultServer.setTestHandler(new ResponseHandler(null));

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(DefaultServer.getServerUri());
        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());

        Header[] values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());
    }

    @Test
    public void testBasicAuthenticationAvailable() {
        assertTrue("Basic Authentication Supported", httpAuthenticationFactory.getMechanismNames().contains("BASIC"));
    }

    @Test
    public void testBasicAuthentication() throws Exception {
        /*
         * Full Chain Set Up
         */
        HttpHandler nextHandler = new ResponseHandler(httpAuthenticationFactory.getSecurityDomain());
        nextHandler = new ElytronRunAsHandler(nextHandler);
        nextHandler = new BlockingHandler(nextHandler);
        nextHandler = new AuthenticationCallHandler(nextHandler);
        nextHandler = new AuthenticationConstraintHandler(nextHandler);
        nextHandler = new ElytronContextAssociationHandler(nextHandler, BasicAuthenticationTest::getAuthenticationMechanisms);

        DefaultServer.setTestHandler(nextHandler);

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(DefaultServer.getServerUri());
        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.UNAUTHORIZED, result.getStatusLine().getStatusCode());

        Header[] values = result.getHeaders(WWW_AUTHENTICATE.toString());
        String header = getAuthHeader(BASIC, values);
        assertEquals(BASIC + " realm=\"Elytron Realm\"", header);
        readResponse(result);

        get = new HttpGet(DefaultServer.getServerUri());
        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + FlexBase64.encodeString("elytron:Coleoptera".getBytes(), false));
        result = httpClient.execute(get);
        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());

        values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());

        values = result.getHeaders("UndertowUser");
        assertEquals(1, values.length);
        assertEquals("elytron", values[0].getValue());

        values = result.getHeaders("ElytronUser");
        assertEquals(1, values.length);
        assertEquals("elytron", values[0].getValue());

        readResponse(result);
    }

    public static String readResponse(final HttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        if(entity == null) {
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

    protected static String getAuthHeader(final HttpString prefix, final Header[] values) {
        for (Header current : values) {
            String currentValue = current.getValue();
            if (currentValue.startsWith(prefix.toString())) {
                return currentValue;
            }
        }

        fail("Expected header not found.");
        return null; // Unreachable
    }

    private static HttpServerAuthenticationMechanism createMechanism(final String mechanismName) {
        try {
            return httpAuthenticationFactory.createMechanism(mechanismName);
        } catch (HttpAuthenticationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static List<HttpServerAuthenticationMechanism> getAuthenticationMechanisms() {
        return httpAuthenticationFactory.getMechanismNames().stream()
            .map(BasicAuthenticationTest::createMechanism)
            .filter(m -> m != null)
            .collect(Collectors.toList());
    }

}
