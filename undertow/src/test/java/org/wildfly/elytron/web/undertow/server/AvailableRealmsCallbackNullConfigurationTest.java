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
import org.junit.Test;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.util.LogHandler;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;

import java.io.File;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.jboss.logmanager.Level.ERROR;
import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:mskaceli@redhat.com">Marek Skacelik</a>
 */
public class AvailableRealmsCallbackNullConfigurationTest extends AbstractAvailableRealmsCallbackTest {

    private final LogHandler logHandler = new LogHandler("target" + File.separator + "test.log");

    public AvailableRealmsCallbackNullConfigurationTest() throws Exception {
    }

    @Test
    public void testNullConfiguration() throws Exception {
        final String expectedException = "java.lang.IllegalStateException: ELY01119: Unable to resolve MechanismConfiguration for mechanismType='null'";
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet httpGet = new HttpGet(server.createUri());
        HttpResponse response = httpClient.execute(httpGet);

        assertEquals(SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
        logHandler.assertLogsContain(expectedException, ERROR);
    }
    @Override
    UndertowServer createUndertowServer() throws Exception {
        return UndertowCoreServer.builder()
                .setSecurityDomain(doCreateSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setMechanismConfigurationSelectorSupplier(() -> MechanismConfigurationSelector.constantSelector(null))
                .build();
    }
}
