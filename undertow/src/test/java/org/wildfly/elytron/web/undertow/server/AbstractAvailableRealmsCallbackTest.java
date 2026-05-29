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

import org.junit.Rule;
import org.wildfly.elytron.web.undertow.common.AbstractHttpServerMechanismTest;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;

/**
 * @author <a href="mailto:mskaceli@redhat.com">Marek Skacelik</a>
 */
public abstract class AbstractAvailableRealmsCallbackTest extends AbstractHttpServerMechanismTest {

    @Rule
    public UndertowServer server = createUndertowServer();

    protected AbstractAvailableRealmsCallbackTest() throws Exception {
    }

    @Override
    protected String getMechanismName() {
        // no filtering
        return null;
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        return SecurityDomain.builder()
                .setDefaultRealmName("SimpleRealm")
                .addRealm("SimpleRealm", new SimpleMapBackedSecurityRealm()).build().build();
    }

    abstract UndertowServer createUndertowServer() throws Exception;

}