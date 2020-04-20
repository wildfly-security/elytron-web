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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;

import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.util.SessionInvalidationHandler;
import org.wildfly.elytron.web.undertow.server.util.TestResponseHandler;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.http.HttpAuthenticationFactory;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import io.undertow.Handlers;
import io.undertow.Undertow;
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

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UndertowCoreServer extends UndertowServer {

    private Undertow server;
    private HttpHandler rootHttpHandler = null;

    public UndertowCoreServer(HttpHandler root, int port, String deploymentName, Supplier<SSLContext> serverSslContext) {
        super(serverSslContext, port, deploymentName);
        this.rootHttpHandler = root;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return super.apply(base, description);
    }

    @Override
    protected void before() throws Throwable {
        Undertow.Builder builder = Undertow.builder().setBufferSize(512);

        if (serverSslContext != null) {
            builder.addHttpsListener(port,  "localhost", serverSslContext.get(), rootHttpHandler);
        } else {
            builder.addHttpListener(port, "localhost", rootHttpHandler);
        }

        server = builder.build();
        server.start();
    }

    @Override
    protected void after() {
        if (server == null) {
            return;
        }
        server.stop();
        server = null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private SecurityDomain securityDomain;
        private Function<Map<String, String>, HttpServerAuthenticationMechanismFactory> configuredFactoryFunction;
        private SessionManager sessionManager;
        private AuthenticationMode authenticationMode;
        private int port = 7776;
        private String deploymentName;
        private Supplier<SSLContext> serverSslContext;
        private String remoteUser = null;

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            this.securityDomain = securityDomain;

            return this;
        }

        public Builder setMechanismFactoryFunction(final Function<Map<String, String>, HttpServerAuthenticationMechanismFactory> configuredFactoryFunction) {
            this.configuredFactoryFunction = configuredFactoryFunction;

            return this;
        }

        public Builder setPort(final int port) {
            this.port = port;

            return this;
        }

        public Builder setSessionManager(final SessionManager sessionManager) {
            this.sessionManager = sessionManager;

            return this;
        }

        public Builder setAuthenticationMode(final AuthenticationMode authenticationMode) {
            this.authenticationMode = authenticationMode;

            return this;
        }

        public Builder setDeploymentName(final String deploymentName) {
            this.deploymentName = deploymentName;

            return this;
        }

        public Builder setSslContext(final Supplier<SSLContext> serverSslContext) {
            this.serverSslContext = serverSslContext;

            return this;
        }

        public Builder setRemoteUser(final String remoteUser) {
            this.remoteUser = remoteUser;

            return this;
        }

        public Builder setSslContext(final SSLContext serverSslcontext) {
            this.serverSslContext = () -> serverSslcontext;

            return this;
        }

        public UndertowServer build() {
            return new UndertowCoreServer(createRootHttpHandler(), port, deploymentName, serverSslContext);
        }

        private HttpAuthenticationFactory createHttpAuthenticationFactory(String contextPath) throws Exception {
            Map<String, String> properties = new HashMap<>();

            properties.put(HttpConstants.CONFIG_LOGIN_PAGE, contextPath + "/login.html");
            properties.put(HttpConstants.CONFIG_ERROR_PAGE, contextPath + "/error.html");

            HttpServerAuthenticationMechanismFactory factory = configuredFactoryFunction.apply(properties);

            return HttpAuthenticationFactory.builder()
                    .setSecurityDomain(securityDomain)
                    .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                            MechanismConfiguration.builder()
                                    .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                    .build()))
                    .setFactory(factory)
                    .build();
        }


        private HttpHandler createRootHttpHandler() {
            try {
                String deploymentName = (sessionManager != null) ? sessionManager.getDeploymentName() : null;
                String contextPath = (deploymentName != null) ? "/" + deploymentName : "";

                HttpAuthenticationFactory httpAuthenticationFactory = createHttpAuthenticationFactory(contextPath);
                HttpHandler rootHandler = new ElytronRunAsHandler(new SessionInvalidationHandler(new TestResponseHandler(securityDomain)));

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

                    elytronContextHandlerBuilder.setHttpExchangeSupplier(exchange ->
                            {
                                exchange.putAttachment(HttpServerExchange.REMOTE_USER, remoteUser);
                                return new ElytronHttpExchange(exchange, Collections.emptyMap(), sessionListener);
                            });

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
}
