/*
 * Copyright 2018 Red Hat, Inc.
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

import static java.security.AccessController.doPrivileged;
import static org.wildfly.elytron.web.undertow.server.servlet.ElytronHttpServletExchange.APPLICATION_SCOPE_RESOLVER;
import static org.wildfly.elytron.web.undertow.server.servlet.IdentityMapping.mapIdentity;
import static org.wildfly.security.http.HttpConstants.CONFIG_CONTEXT_PATH;
import static org.wildfly.security.http.HttpConstants.CONFIG_ERROR_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_LOGIN_PAGE;
import static org.wildfly.security.http.HttpConstants.CONFIG_REALM;

import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import org.jboss.metadata.javaee.jboss.RunAsIdentityMetaData;
import org.wildfly.elytron.web.undertow.server.ElytronRunAsHandler;
import org.wildfly.elytron.web.undertow.server.ScopeSessionListener;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;
import org.wildfly.security.manager.WildFlySecurityManager;

import io.undertow.server.HttpHandler;
import io.undertow.servlet.api.AuthMethodConfig;
import io.undertow.servlet.api.AuthorizationManager;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.LoginConfig;

/**
 * A utility class to take relevant Elytron component instances and apply them to an Undertow {@link DeploymentInfo} to apply
 * Elytron based authentication to a deployment.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthenticationManager {

    private final Builder builder;

    AuthenticationManager(Builder builder) {
        // A builder can only be built once and further modifications are prohibited so we can cache it.
        this.builder = builder;
    }

    /**
     * Configure the {@link DeploymentInfo} so the deployment will use Elytron security based on the parameters used to
     * initialise this {@link AuthenticationManaer}.
     *
     * @param deploymentInfo the {@link DeploymentInfo} to configure.
     */
    public void configure(DeploymentInfo deploymentInfo) {
        final ScopeSessionListener scopeSessionListener = ScopeSessionListener.builder()
                .addScopeResolver(Scope.APPLICATION, APPLICATION_SCOPE_RESOLVER)
                .build();

        final SecurityDomain securityDomain = builder.httpAuthenticationFactory.getSecurityDomain();

        if (WildFlySecurityManager.isChecking()) {
            doPrivileged((PrivilegedAction<Void>) () -> {
                securityDomain.registerWithClassLoader(deploymentInfo.getClassLoader());
                return null;
            });
        } else {
            securityDomain.registerWithClassLoader(deploymentInfo.getClassLoader());
        }

        deploymentInfo.addSessionListener(scopeSessionListener);

        final Function<String, RunAsIdentityMetaData> runAsMapper = builder.runAsMapper;
        deploymentInfo.addInnerHandlerChainWrapper(h -> finalSecurityHandlers(h, securityDomain, runAsMapper));
        deploymentInfo.setInitialSecurityWrapper(h -> initialSecurityHandler(deploymentInfo, h, securityDomain, scopeSessionListener));
        if (runAsMapper != null) {
            deploymentInfo.addLifecycleInterceptor(new RunAsLifecycleInterceptor(runAsMapper, securityDomain));
        }

        if (builder.authorizationManager != null) {
            deploymentInfo.setAuthorizationManager(builder.authorizationManager);
        } else {
            // TODO - If we can discover the SecurityDomain at runtime this could also become a singleton.
            deploymentInfo.setAuthorizationManager(new ElytronAuthorizationManager(securityDomain));
        }
    }

    private HttpHandler initialSecurityHandler(final DeploymentInfo deploymentInfo, HttpHandler toWrap, SecurityDomain securityDomain, ScopeSessionListener scopeSessionListener) {
        final Collection<String> availableMechanisms = builder.httpAuthenticationFactory.getMechanismNames();
        if (availableMechanisms.isEmpty()) {
            throw new IllegalStateException("There are no mechanisms available from the HttpAuthenticationFactory.");
            //throw ROOT_LOGGER.noMechanismsAvailable();
        }

        Map<String, String> tempBaseConfiguration = new HashMap<>();
        tempBaseConfiguration.put(CONFIG_CONTEXT_PATH, deploymentInfo.getContextPath());

        LoginConfig loginConfig = deploymentInfo.getLoginConfig();
        if (loginConfig != null) {
            String realm = loginConfig.getRealmName();
            if (realm != null) tempBaseConfiguration.put(CONFIG_REALM, realm);
            String loginPage = loginConfig.getLoginPage();
            if (loginPage != null) tempBaseConfiguration.put(CONFIG_LOGIN_PAGE, loginPage);
            String errorPage = loginConfig.getErrorPage();
            if (errorPage != null) tempBaseConfiguration.put(CONFIG_ERROR_PAGE, errorPage);
        }
        final Map<String, String> baseConfiguration = Collections.unmodifiableMap(tempBaseConfiguration);

        final Map<String, Map<String, String>> selectedMechanisms = new LinkedHashMap<>();
        if (builder.overrideDeploymentConfig || (loginConfig == null)) {
            final Map<String, String> mechanismConfiguration = baseConfiguration;
            for (String n : availableMechanisms) {
                selectedMechanisms.put(n, mechanismConfiguration);
            }
        } else {
            final List<AuthMethodConfig> authMethods = loginConfig.getAuthMethods();
            if (authMethods.isEmpty()) {
                throw new IllegalStateException("No authentication mechanisms have been selected.");
                //throw ROOT_LOGGER.noMechanismsSelected();
            }
            for (AuthMethodConfig c : authMethods) {
                String name = c.getName();
                if (availableMechanisms.contains(name) == false) {
                    throw new IllegalStateException(String.format("The required mechanism '%s' is not available in mechanisms %s from the HttpAuthenticationFactory.", name, availableMechanisms));
                    //throw ROOT_LOGGER.requiredMechanismNotAvailable(name, availableMechanisms);
                }

                Map<String, String> mechanismConfiguration;
                Map<String, String> additionalProperties = c.getProperties();
                if (additionalProperties != null) {
                    mechanismConfiguration = new HashMap<>(baseConfiguration);
                    mechanismConfiguration.putAll(additionalProperties);
                    mechanismConfiguration = Collections.unmodifiableMap(mechanismConfiguration);
                } else {
                    mechanismConfiguration = baseConfiguration;
                }
                selectedMechanisms.put(name, mechanismConfiguration);
            }
        }

        final String applicationContext = deploymentInfo.getHostName() + " " + deploymentInfo.getContextPath();

        HttpHandler contextAssociationHander = ElytronServletContextAssociationHandler.builder()
                .setApplicationContext(applicationContext)
                .setEnableJaspi(builder.enableJaspi)
                .setIntegratedJaspi(builder.integratedJapi)
                .setNext(toWrap)
                .setSecurityDomain(securityDomain)
                .setMechanismSupplier(() -> getAuthenticationMechanisms(selectedMechanisms))
                .setAuthenticationMode(deploymentInfo.getAuthenticationMode())
                .setHttpExchangeSupplier(httpServerExchange -> new ElytronHttpServletExchange(httpServerExchange, scopeSessionListener))
                .build();
        return new CleanUpHandler(contextAssociationHander);
    }

    private HttpHandler finalSecurityHandlers(HttpHandler toWrap, final SecurityDomain securityDomain, final Function<String, RunAsIdentityMetaData> runAsMapper) {
        return runAsMapper != null ? new ElytronRunAsHandler(toWrap, (s, e) -> mapIdentity(s, securityDomain, e, runAsMapper)) : new ElytronRunAsHandler(toWrap);
    }

    private List<HttpServerAuthenticationMechanism> getAuthenticationMechanisms(Map<String, Map<String, String>> selectedMechanisms) {
        List<HttpServerAuthenticationMechanism> mechanisms = new ArrayList<>(selectedMechanisms.size());
        UnaryOperator<HttpServerAuthenticationMechanismFactory> singleSignOnTransformer = builder.httpAuthenticationFactoryTransformer;
        for (Entry<String, Map<String, String>> entry : selectedMechanisms.entrySet()) {
            try {
                UnaryOperator<HttpServerAuthenticationMechanismFactory> factoryTransformation = f -> {
                    HttpServerAuthenticationMechanismFactory factory = new PropertiesServerMechanismFactory(f, entry.getValue());
                    return (singleSignOnTransformer != null) ? singleSignOnTransformer.apply(factory) : factory;
                };
                HttpServerAuthenticationMechanism mechanism =  builder.httpAuthenticationFactory.createMechanism(entry.getKey(), factoryTransformation);
                if (mechanism != null) mechanisms.add(mechanism);
            } catch (HttpAuthenticationException e) {
                throw new IllegalStateException(e);
            }
        }

        return mechanisms;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private HttpAuthenticationFactory httpAuthenticationFactory;
        private boolean overrideDeploymentConfig;
        private AuthorizationManager authorizationManager;
        private UnaryOperator<HttpServerAuthenticationMechanismFactory> httpAuthenticationFactoryTransformer;
        private Function<String, RunAsIdentityMetaData> runAsMapper;
        private boolean enableJaspi = false;
        private boolean integratedJapi = true;

        private boolean built = false;

        /**
         * Set the {@link HttpAuthenticationFactory} to be used to secure the deployment.
         *
         * @param httpAuthenticationFactory the {@link HttpAuthenticationFactory} to be used to secure the deployment.
         * @return this {@link Builder}
         */
        public Builder setHttpAuthenticationFactory(final HttpAuthenticationFactory httpAuthenticationFactory) {
            assertNotBuilt();
            this.httpAuthenticationFactory = httpAuthenticationFactory;

            return this;
        }

        /**
         * Set an {@link AuthorizationManager} for the deployment, if none is provided the default Elytron AuthorizationManager will be used instead.
         *
         * @param authorizationManagerSupplier an {@link AuthorizationManager} for the deployment.
         * @return this {@link Builder}
         */
        public Builder setAuthorizationManager(final AuthorizationManager authorizationManager) {
            assertNotBuilt();
            this.authorizationManager = authorizationManager;

            return this;
        }

        /**
         * Sets if the deployments authentication mechanisms should be overridden, where they are overridden all of the
         * mechanisms from the HttpAuthenticationFactory will be used with no additional filtering.
         *
         * @param overrideDeploymentConfig should the mechanisms specified in the deployment be overridden.
         * @return this {@link Builder}
         */
        public Builder setOverrideDeploymentConfig(final boolean overrideDeploymentConfig) {
            assertNotBuilt();
            this.overrideDeploymentConfig = overrideDeploymentConfig;

            return this;
        }

        /**
         * Sets a {@link UnaryOperator} to transform the {@link HttpAuthenticationFactory}.
         *
         * @param httpAuthenticationFactoryTransformer a {@link UnaryOperator} to transform the {@link HttpAuthenticationFactory}
         * @return this {@link Builder}
         */
        public Builder setHttpAuthenticationFactoryTransformer (final UnaryOperator<HttpServerAuthenticationMechanismFactory> httpAuthenticationFactoryTransformer) {
            assertNotBuilt();
            this.httpAuthenticationFactoryTransformer = httpAuthenticationFactoryTransformer;

            return this;
        }

        /**
         * Set the run as mapper for identfying run {@link RunAsIdentityMetaData}.
         *
         * @param runAsMapper the run as mapper for identfying run {@link RunAsIdentityMetaData}.
         * @return this {@link Builder}
         */
        public Builder setRunAsMapper(final Function<String, RunAsIdentityMetaData> runAsMapper) {
            assertNotBuilt();
            this.runAsMapper = runAsMapper;

            return this;
        }

        /**
         * Set if JASPI authentication should be enabled.
         *
         * @param enableJaspi if JASPI authentication should be enabled.
         * @return this {@link Builder}
         */
        public Builder setEnableJaspi(final boolean enableJaspi) {
            assertNotBuilt();
            this.enableJaspi = enableJaspi;

            return this;
        }

        /**
         * Set if JASPI authentication should be integrated with the {@link SecurityDomain}, if not integrated AdHoc identities
         * will be created instead from the domain.
         *
         * @param integratedJaspi if JASPI authentication should be integrated with the {@link SecurityDomain}
         * @return this {@link Builder}
         */
        public Builder setIntegratedJaspi(final boolean integratedJaspi) {
            assertNotBuilt();
            this.integratedJapi = integratedJaspi;

            return this;
        }

        /**
         * Assemble the supplied configuration into a complete {@link AuthenticationManager}.
         *
         * @return a configured {@link AuthenticationManager}.
         */
        public AuthenticationManager build() {
            assertNotBuilt();
            built = true;
            return new AuthenticationManager(this);
        }

        void assertNotBuilt() {
            if (built) {
                throw new IllegalStateException("Builder already built.");
            }
        }
    }
}
