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

import static io.undertow.util.Headers.AUTHORIZATION;
import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.permission.PermissionVerifier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.undertow.util.StatusCodes;

/**
 * Test case to {@link org.wildfly.security.http.impl.BearerTokenAuthenticationMechanism}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class BearerTokenAuthenticationBase extends AbstractHttpServerMechanismTest {

    protected BearerTokenAuthenticationBase() throws Exception {
    }

    @Rule
    public UndertowServer server = createUndertowServer();

    private KeyPair keyPair;

    @Test
    public void testNoBearerToken() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri());
        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.UNAUTHORIZED, result.getStatusLine().getStatusCode());
        assertEquals("Bearer realm=\"Elytron Realm\"", result.getFirstHeader(HttpConstants.WWW_AUTHENTICATE).getValue());
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri());

        setBearerToken(get, createToken("alice", new Date(new Date().getTime() + 10000)));

        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());
        assertSuccessfulResponse(result, "alice");
    }

    @Test
    public void testTokenWithInvalidExpirationTime() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri());

        // send token with an invalid expiration time
        setBearerToken(get, createToken("alice", new Date(new Date().getTime() - 10000)));

        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.UNAUTHORIZED, result.getStatusLine().getStatusCode());
    }

    @Test
    public void testTokenWithInvalidSignature() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri());

        // send token with an invalid expiration time
        setBearerToken(get, createToken("alice", new Date(new Date().getTime() + 10000), generateKeyPair().getPrivate()));

        HttpResponse result = httpClient.execute(get);
        assertEquals(StatusCodes.UNAUTHORIZED, result.getStatusLine().getStatusCode());
    }

    @Override
    protected String getMechanismName() {
        return "BEARER_TOKEN";
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", TokenSecurityRealm.builder().principalClaimName("username")
                .validator(JwtValidator.builder().publicKey(getKeyPair().getPublic()).build()).build())
                .build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));

        return builder.build();
    }

    private void setBearerToken(HttpGet get, String token) throws JOSEException {
        get.addHeader(AUTHORIZATION.toString(), "Bearer" + " " + token);
    }

    private String createToken(String userName, Date expirationDate) throws JOSEException, NoSuchAlgorithmException {
        return createToken(userName, expirationDate, getKeyPair().getPrivate());
    }

    private String createToken(String userName, Date expirationDate, PrivateKey signingKey) throws JOSEException, NoSuchAlgorithmException {
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();

        claimsSet.subject("123445667");
        claimsSet.claim("username", userName);
        claimsSet.audience("resource-server");
        claimsSet.issuer("elytron.org");
        claimsSet.expirationTime(expirationDate);

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.build());

        signedJWT.sign(new RSASSASigner(signingKey));

        return signedJWT.serialize();
    }

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        if (keyPair == null) {
            keyPair = generateKeyPair();
        }
        return keyPair;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    protected abstract UndertowServer createUndertowServer() throws Exception;
}
