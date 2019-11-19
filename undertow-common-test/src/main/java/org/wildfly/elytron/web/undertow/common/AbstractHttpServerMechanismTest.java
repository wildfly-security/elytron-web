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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.bearer.BearerMechanismFactory;
import org.wildfly.security.http.cert.ClientCertMechanismFactory;
import org.wildfly.security.http.digest.DigestMechanismFactory;
import org.wildfly.security.http.form.FormMechanismFactory;
import org.wildfly.security.http.spnego.SpnegoMechanismFactory;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public abstract class AbstractHttpServerMechanismTest {

    private static final Provider ELYTRON_PROVIDER = new WildFlyElytronProvider();

    @BeforeClass
    public static void installProvider() {
        Security.addProvider(ELYTRON_PROVIDER);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(ELYTRON_PROVIDER.getName());
    }

    private SecurityDomain securityDomain;

    protected void assertSuccessfulResponse(HttpResponse result, String expectedUserName) {
        Header[] values;
        values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());

        values = result.getHeaders("UndertowUser");
        assertEquals(1, values.length);
        assertEquals(expectedUserName, values[0].getValue());

        values = result.getHeaders("ElytronUser");
        assertEquals(1, values.length);
        assertEquals(expectedUserName, values[0].getValue());
    }

    protected void assertSuccessfulUnconstraintResponse(HttpResponse result, String expectedUserName) {
        Header[] values;
        values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());

        if (expectedUserName != null) {
            values = result.getHeaders("UndertowUser");
            assertEquals(1, values.length);
            assertEquals(expectedUserName, values[0].getValue());

            values = result.getHeaders("ElytronUser");
            assertEquals(1, values.length);
            assertEquals(expectedUserName, values[0].getValue());
        } else {
            values = result.getHeaders("UndertowUser");
            assertEquals(0, values.length);

            values = result.getHeaders("ElytronUser");
            assertEquals(1, values.length);
            assertEquals("anonymous", values[0].getValue());
        }
    }

    protected void assertLoginPage(HttpResponse response) throws Exception {
        assertTrue(EntityUtils.toString(response.getEntity()).contains("Login Page"));
    }

    protected HttpServerAuthenticationMechanismFactory getHttpServerAuthenticationMechanismFactory(Map<String, ?> properties) {
        HttpServerAuthenticationMechanismFactory delegate = new AggregateServerMechanismFactory(new BasicMechanismFactory(), new BearerMechanismFactory(),
                new ClientCertMechanismFactory(), new DigestMechanismFactory(), new FormMechanismFactory(),
                new SpnegoMechanismFactory());
        return new PropertiesServerMechanismFactory(new FilterServerMechanismFactory(delegate, true, getMechanismName()), properties);
    }

    protected abstract String getMechanismName();

    protected SecurityDomain getSecurityDomain() throws Exception {
        if (this.securityDomain == null) {
            this.securityDomain = doCreateSecurityDomain();
        }

        return this.securityDomain;
    }

    protected abstract SecurityDomain doCreateSecurityDomain() throws Exception;


}
