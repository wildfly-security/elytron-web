/*
 * Copyright 2024 Red Hat, Inc.
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

package org.wildfly.elytron.web.undertow.server.servlet;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.infinispan.commons.configuration.ClassAllowList;
import org.junit.Rule;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.servlet.util.UndertowServletServer.Builder;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnManager;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionIdentifierFactory;
import org.wildfly.security.http.util.sso.SingleSignOnEntry;
import org.wildfly.security.http.util.sso.SingleSignOnManager;
import org.wildfly.security.http.util.sso.SingleSignOnServerMechanismFactory;
import org.wildfly.security.http.util.sso.SingleSignOnSessionFactory;

/**
 * Test case to test HTTP FORM authentication where authentication is backed by Elytron and session replication is enabled.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class FormServletAuthenticationStandaloneSSOTest extends FormAuthenticationSSOBase {

    @Rule
    public final UndertowServer serverA = createUndertowServer(7776);


    public FormServletAuthenticationStandaloneSSOTest() throws Exception {
    }

    @Override
    protected Builder createUndertowServerBuilder(int port) throws Exception {
        return super.createUndertowServerBuilder(port)
            .addAdditionalDeployment("second.war", getContextRootAppB());
    }

    @Override
    protected URI createUriAppA(String alternativePath) throws URISyntaxException {
        return serverA.createUri(alternativePath);
    }

    @Override
    protected URI createUriAppB(String alternativePath) throws URISyntaxException {
        return serverA.createUri(getContextRootAppB(), alternativePath);
    }

    @Override
    protected String getContextRootAppA() {
        return serverA.getContextRoot();
    }

    @Override
    protected String getContextRootAppB() {
        return "/second";
    }

    @Override
    protected HttpServerAuthenticationMechanismFactory getHttpServerAuthenticationMechanismFactory(Map<String, ?> properties) {
        HttpServerAuthenticationMechanismFactory delegate = super.getHttpServerAuthenticationMechanismFactory(properties);

        ClassAllowList allowList = new ClassAllowList();
        allowList.addRegexps(".*");

        final ConcurrentMap<String, SingleSignOnEntry> cache = new ConcurrentHashMap<>();
        SingleSignOnManager manager = new DefaultSingleSignOnManager(cache, new DefaultSingleSignOnSessionIdentifierFactory(), (id, entry) -> cache.put(id, entry));
        SingleSignOnServerMechanismFactory.SingleSignOnConfiguration signOnConfiguration =
                new SingleSignOnServerMechanismFactory.SingleSignOnConfiguration("JSESSIONSSOID", null,
                        "/", false, false);

        if (keyPairSupplier == null) {
            keyPairSupplier = new KeyPairSupplier();
        }
        SingleSignOnSessionFactory singleSignOnSessionFactory = new DefaultSingleSignOnSessionFactory(manager, keyPairSupplier.get());

        return new SingleSignOnServerMechanismFactory(delegate, singleSignOnSessionFactory, signOnConfiguration);
    }

}
