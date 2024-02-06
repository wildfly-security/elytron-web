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

package org.wildfly.elytron.web.undertow.server.servlet.util;

import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.servlet.AuthenticationManager;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.server.handlers.PathHandler;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.WebResourceCollection;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UndertowServletServer extends UndertowServer {

    private static final String CONTEXT_ROOT = "/helloworld";
    private static final String SERVLET = "/secured";

    private final SecurityDomain securityDomain;
    private final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory;
    private final String authenticationMechanism;
    private String deploymentName;

    private Undertow undertowServer;

    protected UndertowServletServer(Supplier<SSLContext> serverSslContext, int port, String contextRoot, final String authenticationMechanism,
            final SecurityDomain securityDomain, final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory, final String deploymentName) {
        super(serverSslContext, port, contextRoot, SERVLET);
        this.authenticationMechanism = authenticationMechanism;
        this.securityDomain = securityDomain;
        this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;
        this.deploymentName = deploymentName;
    }

    @Override
    protected void before() throws Throwable {
        DeploymentInfo deploymentInfo = Servlets.deployment()
                .setClassLoader(TestServlet.class.getClassLoader())
                .setContextPath(contextRoot)
                .setDeploymentName(deploymentName)
                .setLoginConfig(new LoginConfig(authenticationMechanism, "Elytron Realm", "/login", "/error"))
                .addSecurityConstraint(new SecurityConstraint()
                        .addWebResourceCollection(new WebResourceCollection()
                                .addUrlPattern(SERVLET + "/*"))
                        .addRoleAllowed("**")
                        .setEmptyRoleSemantic(SecurityInfo.EmptyRoleSemantic.DENY))
                .addServlets(Servlets.servlet(TestServlet.class)
                        .addMapping("/")
                        .addMapping(SERVLET)
                        .addMapping("/unsecure"),
                        Servlets.servlet(LoginServlet.class)
                            .addMapping("/login"),
                        Servlets.servlet(LogoutServlet.class)
                            .addMapping("/logout"));

        HttpAuthenticationFactory httpAuthenticationFactory =  HttpAuthenticationFactory.builder()
                .setFactory(httpServerAuthenticationMechanismFactory)
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .build();

        AuthenticationManager authManager = AuthenticationManager.builder()
                .setHttpAuthenticationFactory(httpAuthenticationFactory)
                .setEnableJaspi(false)
                .build();
        authManager.configure(deploymentInfo);

        DeploymentManager deployManager = Servlets.defaultContainer().addDeployment(deploymentInfo);
        deployManager.deploy();

        PathHandler path = Handlers.path(Handlers.redirect(contextRoot))
                .addPrefixPath(contextRoot, deployManager.start());

        Undertow.Builder undertowBuilder = Undertow.builder()
                .setHandler(path);

        if (serverSslContext != null) {
            undertowBuilder.addHttpsListener(port, "localhost", serverSslContext.get());
        } else {
            undertowBuilder.addHttpListener(port, "localhost");
        }

        undertowServer = undertowBuilder.build();

        undertowServer.start();
    }

    @Override
    protected void after() {
        undertowServer.stop();
        SecurityDomain.unregisterClassLoader(TestServlet.class.getClassLoader());
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String contextRoot = CONTEXT_ROOT;
        private String authenticationMechanism;
        private SecurityDomain securityDomain;
        private int port = 7776;
        private Supplier<SSLContext> serverSslContext;
        private HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory;
        String deploymentName = "helloworld.war";

        public Builder setAuthenticationMechanism(final String authenticationMechanism) {
            this.authenticationMechanism = authenticationMechanism;

            return this;
        }

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            this.securityDomain = securityDomain;

            return this;
        }

        public Builder setContextRoot(final String contextRoot) {
            this.contextRoot = contextRoot;

            return this;
        }

        public Builder setPort(final int port) {
            this.port = port;

            return this;
        }

        public Builder setSslContext(final Supplier<SSLContext> serverSslContext) {
            this.serverSslContext = serverSslContext;

            return this;
        }

        public Builder setSslContext(final SSLContext serverSslcontext) {
            this.serverSslContext = () -> serverSslcontext;

            return this;
        }

        public Builder setHttpServerAuthenticationMechanismFactory(final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory) {
            this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;

            return this;
        }

        public Builder setDeploymentName(final String deploymentName) {
            this.deploymentName = deploymentName;
            return this;
        }

        public UndertowServer build() throws Exception {
            return new UndertowServletServer(serverSslContext, port, contextRoot, authenticationMechanism, securityDomain, httpServerAuthenticationMechanismFactory, deploymentName);
        }


    }

}
