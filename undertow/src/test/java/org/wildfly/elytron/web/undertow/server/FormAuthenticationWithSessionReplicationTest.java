/*
 * Copyright 2019 Red Hat, Inc.
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

import org.junit.Ignore;
import org.wildfly.elytron.web.undertow.common.FormAuthenticationWithSessionReplicationBase;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.util.InfinispanSessionManager;

import io.undertow.server.session.SessionManager;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Ignore("https://github.com/wildfly-security/elytron-web/issues/45")
public class FormAuthenticationWithSessionReplicationTest extends FormAuthenticationWithSessionReplicationBase {

    public FormAuthenticationWithSessionReplicationTest() throws Exception {
        super();
    }

    @Override
    protected UndertowServer createUndertowServer(int port) throws Exception {
        SessionManager sessionManager = new InfinispanSessionManager(String.valueOf(port));

        return UndertowCoreServer.builder()
                .setSecurityDomain(getSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setSessionManager(sessionManager)
                .setPort(port)
                .setDeploymentName(sessionManager.getDeploymentName())
                .build();
    }

}
