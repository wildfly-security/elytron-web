/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2019 Red Hat, Inc. and/or its affiliates.
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

import org.wildfly.elytron.web.undertow.common.BasicAuthenticationBase;
import org.wildfly.elytron.web.undertow.common.UndertowServer;

import io.undertow.security.api.AuthenticationMode;

/**
 * Test case to test HTTP BASIC authentication where authentication is backed by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BasicAuthenticationTest extends BasicAuthenticationBase {

    public BasicAuthenticationTest() throws Exception {
        super();
    }

    @Override
    protected UndertowServer createUndertowServer() throws Exception {
        return UndertowCoreServer.builder()
                .setSecurityDomain(getSecurityDomain())
                .setMechanismFactoryFunction(this::getHttpServerAuthenticationMechanismFactory)
                .setAuthenticationMode(getAuthenticationMode())
                .build();
    }

    protected AuthenticationMode getAuthenticationMode() {
        return null;
    }

}
