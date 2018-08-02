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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import io.undertow.Handlers;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.session.SessionAttachmentHandler;
import io.undertow.server.session.SessionCookieConfig;
import io.undertow.server.session.SessionManager;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.wildfly.elytron.web.undertow.server.util.SessionInvalidationHandler;
import org.wildfly.elytron.web.undertow.server.util.TestResponseHandler;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
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

    protected HttpAuthenticationFactory createHttpAuthenticationFactory(String contextPath) throws Exception {
        SecurityDomain securityDomain = getSecurityDomain();

        Map<String, String> properties = new HashMap<>();

        properties.put(HttpConstants.CONFIG_LOGIN_PAGE, contextPath + "/login.html");
        properties.put(HttpConstants.CONFIG_ERROR_PAGE, contextPath + "/error.html");

        HttpServerAuthenticationMechanismFactory factory = doCreateHttpServerMechanismFactory(properties);

        return HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .setFactory(factory)
                .build();
    }

    protected HttpServerAuthenticationMechanismFactory doCreateHttpServerMechanismFactory(Map<String, ?> properties) {
        return new PropertiesServerMechanismFactory(new FilterServerMechanismFactory(new ServerMechanismFactoryImpl(), true, getMechanismName()), properties);
    }

    protected abstract String getMechanismName();

    protected SecurityDomain getSecurityDomain() throws Exception {
        if (this.securityDomain == null) {
            this.securityDomain = doCreateSecurityDomain();
        }

        return this.securityDomain;
    }

    protected abstract SecurityDomain doCreateSecurityDomain() throws Exception;

    protected HttpHandler createRootHttpHandler() {
        return createRootHttpHandler(null);
    }

    protected HttpHandler createRootHttpHandler(SessionManager sessionManager) {
        return createRootHttpHandler(sessionManager, null);
    }

    protected HttpHandler createRootHttpHandler(SessionManager sessionManager, AuthenticationMode authenticationMode) {
        try {
            String deploymentName = (sessionManager != null) ? sessionManager.getDeploymentName() : null;
            String contextPath = (deploymentName != null) ? "/" + deploymentName : "";

            HttpAuthenticationFactory httpAuthenticationFactory = createHttpAuthenticationFactory(contextPath);
            HttpHandler rootHandler = new ElytronRunAsHandler(new SessionInvalidationHandler(new TestResponseHandler(getSecurityDomain())));

            rootHandler = new BlockingHandler(rootHandler);
            rootHandler = new AuthenticationCallHandler(rootHandler);
            rootHandler = new AuthenticationConstraintHandler(rootHandler) {
                @Override
                protected boolean isAuthenticationRequired(HttpServerExchange exchange) {
                    if (exchange.getRelativePath().equals("/unsecure")) {
                        return false;
                    } else {
                        return true;
                    }
                }
            };
            ElytronContextAssociationHandler.Builder elytronContextHandlerBuilder = ElytronContextAssociationHandler.builder()
                    .setNext(rootHandler)
                    .setAuthenticationMode(authenticationMode)
                    .setMechanismSupplier(() -> httpAuthenticationFactory.getMechanismNames().stream()
                            .map(mechanismName -> {
                                try {
                                    return httpAuthenticationFactory.createMechanism(mechanismName);
                                } catch (HttpAuthenticationException e) {
                                    throw new RuntimeException("Failed to create mechanism.", e);
                                }
                            })
                            .filter(m -> m != null)
                            .collect(Collectors.toList()));

            if (sessionManager != null) {
                ScopeSessionListener sessionListener = ScopeSessionListener.builder().build();

                sessionManager.registerSessionListener(sessionListener);

                elytronContextHandlerBuilder.setHttpExchangeSupplier(exchange -> new ElytronHttpExchange(exchange, Collections.emptyMap(), sessionListener));

                sessionManager.start();
            }

            rootHandler = elytronContextHandlerBuilder.build();

            if (sessionManager != null) {
                SessionCookieConfig sessionConfig = new SessionCookieConfig();
                if (!contextPath.isEmpty()) {
                    sessionConfig.setPath(contextPath);
                }
                rootHandler = Handlers.path(new SessionAttachmentHandler(rootHandler, sessionManager, sessionConfig));
            }

            PathHandler finalHandler = Handlers.path();

            finalHandler = finalHandler
                    .addExactPath(contextPath + "/login.html", exchange -> {
                        exchange.getResponseSender().send("Login Page");
                        exchange.endExchange();
                    })
                    .addPrefixPath(contextPath.isEmpty() ? "/" : contextPath, rootHandler);

            return finalHandler;
        } catch (Exception cause) {
            throw new RuntimeException("Could not create root http handler.", cause);
        }
    }
}
