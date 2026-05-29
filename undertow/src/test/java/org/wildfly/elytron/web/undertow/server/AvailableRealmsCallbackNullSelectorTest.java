/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.util.LogHandler;

import java.io.File;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.junit.Assert.assertNotEquals;

/**
 * @author <a href="mailto:mskaceli@redhat.com">Marek Skacelik</a>
 */
public class AvailableRealmsCallbackNullSelectorTest extends AbstractAvailableRealmsCallbackTest {

    private final LogHandler logHandler = new LogHandler("target" + File.separator + "test.log");

        public AvailableRealmsCallbackNullSelectorTest() throws Exception {
    }

    @Ignore("ELY-1745")
    @Test
    public void testNullSelector() throws Exception {
        final String expectedException = "java.lang.NullPointerException";
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet httpGet = new HttpGet(server.createUri());
        // fixme: ELY-1745
        HttpResponse response = httpClient.execute(httpGet);
        assertNotEquals(SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
        logHandler.assertLogsDoNotContain(expectedException);
    }
    @Override
    UndertowServer createUndertowServer() throws Exception {
        return UndertowCoreServer.builder()
                .setSecurityDomain(doCreateSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setMechanismConfigurationSelectorSupplier(() -> null)
                .build();
    }
}
