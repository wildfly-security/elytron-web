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
import static org.junit.Assert.assertEquals;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Test;

import io.undertow.security.api.AuthenticationMode;
import io.undertow.util.FlexBase64;
import io.undertow.util.StatusCodes;

/**
 * Test case to test CONSTRAINT-DRIVEN AuthenticationMode with BASIC authentication
 *
 * @author bspyrkos@redhat.com
 */
public class ConstraintDrivenAuthenticationModeTest extends BasicAuthenticationTest {

    public ConstraintDrivenAuthenticationModeTest() throws Exception {
        super();
    }

    @Override
    protected AuthenticationMode getAuthenticationMode() {
        return AuthenticationMode.CONSTRAINT_DRIVEN;
    }

    @Test
    public void testUnconstrainedAccessWithCorrectPassword() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri("/unsecure"));

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + FlexBase64.encodeString("elytron:Coleoptera".getBytes(), false));

        HttpResponse result = httpClient.execute(get);

        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());
        assertSuccessfulUnconstraintResponse(result, null);
    }

    @Test
    public void testUnconstrainedAccessWithIncorrectPassword() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(server.createUri("/unsecure"));

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + FlexBase64.encodeString("elytron:bad_password".getBytes(), false));

        HttpResponse result = httpClient.execute(get);

        assertEquals(StatusCodes.OK, result.getStatusLine().getStatusCode());
        assertSuccessfulUnconstraintResponse(result, null);
    }
}
