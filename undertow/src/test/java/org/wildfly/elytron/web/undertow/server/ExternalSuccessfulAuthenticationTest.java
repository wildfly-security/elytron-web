/*
 * Copyright 2020 Red Hat, Inc.
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

package org.wildfly.elytron.web.undertow.server;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.common.ExternalAuthenticationBase;
import org.wildfly.elytron.web.undertow.common.UndertowServer;

import io.undertow.server.session.InMemorySessionManager;

/**
 * Test case to test successful authentication with the HTTP External mechanism where authentication is backed by Elytron.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class ExternalSuccessfulAuthenticationTest extends ExternalAuthenticationBase {

    public ExternalSuccessfulAuthenticationTest() throws Exception {
        super();
    }

    @Test
    public void testExternalSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()).build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/external_security_check"));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "remoteUser");
    }

    @Override
    protected UndertowServer createUndertowServer() throws Exception {
        return UndertowCoreServer.builder()
                .setSecurityDomain(getSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setSessionManager(new InMemorySessionManager(null))
                .setRemoteUser("remoteUser")
                .build();
    }


}
