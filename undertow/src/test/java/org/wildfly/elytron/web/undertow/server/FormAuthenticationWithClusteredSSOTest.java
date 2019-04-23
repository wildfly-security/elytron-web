/*
 * Copyright 2016 Red Hat, Inc.
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

import org.wildfly.elytron.web.undertow.common.FormAuthenticationWithClusteredSSOBase;
import org.wildfly.elytron.web.undertow.common.UndertowServer;

import io.undertow.server.session.InMemorySessionManager;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public class FormAuthenticationWithClusteredSSOTest extends FormAuthenticationWithClusteredSSOBase {

    public FormAuthenticationWithClusteredSSOTest() throws Exception {
        super();
    }

    @Override
    protected UndertowServer createUndertowServer(int port) throws Exception {
        InMemorySessionManager sessionManager = new InMemorySessionManager(String.valueOf(port));

        sessionManagers.put(port, sessionManager);

        return UndertowCoreServer.builder()
                .setSecurityDomain(getSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setSessionManager(sessionManager)
                .setPort(port)
                .setDeploymentName("/" + sessionManager.getDeploymentName())
                .build();
    }

}
