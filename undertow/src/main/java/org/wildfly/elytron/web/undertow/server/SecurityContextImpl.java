/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static io.undertow.util.StatusCodes.INTERNAL_SERVER_ERROR;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.List;
import java.util.function.Supplier;

import org.jboss.logging.Logger;
import org.wildfly.security.auth.server.FlexibleIdentityAssociation;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.impl.AbstractSecurityContext;
import io.undertow.server.HttpServerExchange;

/**
 * The Elytron specific {@link SecurityContext} implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SecurityContextImpl extends AbstractSecurityContext {

    private static final Logger log = Logger.getLogger("org.wildfly.security.http");

    private final ElytronHttpExchange httpExchange;

    protected final SecurityDomain securityDomain;
    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final String programmaticMechanismName;
    private Supplier<IdentityCache> identityCacheSupplier;
    private final FlexibleIdentityAssociation flexibleIdentityAssociation;

    private volatile HttpAuthenticator httpAuthenticator;
    private Runnable logoutHandler;
    private AuthenticationMode authMode;

    protected SecurityContextImpl(Builder builder) {
        super(checkNotNullParam("exchange", builder.exchange));
        this.httpExchange = checkNotNullParam("httpExchange", builder.httpExchange);
        this.securityDomain = builder.securityDomain;
        this.mechanismSupplier = builder.mechanismSupplier;
        this.programmaticMechanismName = builder.programmaticMechanismName;
        this.authMode = builder.authMode;
        this.identityCacheSupplier = builder.identityCacheSupplier;
        if(securityDomain != null) {
            this.flexibleIdentityAssociation = securityDomain.getAnonymousSecurityIdentity().createFlexibleAssociation();
        } else {
            this.flexibleIdentityAssociation = null;
        }
    }

    private HttpAuthenticator getHttpAuthenticator() {
        if (httpAuthenticator == null) {
            this.httpAuthenticator = HttpAuthenticator.builder()
                    .setMechanismSupplier(checkNotNullParam("mechanismSupplier", mechanismSupplier))
                    .setIdentityCacheSupplier(identityCacheSupplier)
                    .setProgrammaticMechanismName(checkNotNullParam("programmaticMechanismName", programmaticMechanismName))
                    .setSecurityDomain(securityDomain)
                    .setHttpExchangeSpi(this.httpExchange)
                    .setRequired(isAuthenticationRequired())
                    .setIgnoreOptionalFailures(false) // TODO - Cover this one later.
                    .registerLogoutHandler(this::setLogoutHandler)
                    .build();
        }

        return httpAuthenticator;
    }

    /**
     * @see io.undertow.security.api.SecurityContext#authenticate()
     */
    @Override
    public boolean authenticate() {
        if (isAuthenticated() || (this.authMode == AuthenticationMode.CONSTRAINT_DRIVEN && !isAuthenticationRequired())) {
            return true;
        }

        HttpAuthenticator httpAuthenticator = getHttpAuthenticator();

        try {
            return httpAuthenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            log.trace("Authentication failed.", e);
            exchange.setStatusCode(INTERNAL_SERVER_ERROR);

            return false;
        }
    }

    protected void setLogoutHandler(Runnable runnable) {
        this.logoutHandler = runnable;
    }

    /**
     * @see io.undertow.security.api.SecurityContext#login(java.lang.String, java.lang.String)
     */
    @Override
    public boolean login(String username, String password) {
        HttpAuthenticator httpAuthenticator = getHttpAuthenticator();

        SecurityIdentity securityIdentity = httpAuthenticator.login(username, password);
        if (securityIdentity != null) {
            flexibleIdentityAssociation.setIdentity(securityIdentity);
        }

        return securityIdentity != null;
    }

    @Override
    public void logout() {
        super.logout();
        if (logoutHandler != null) {
            logoutHandler.run();
        }
        if(flexibleIdentityAssociation != null) {
            flexibleIdentityAssociation.setIdentity(securityDomain.getAnonymousSecurityIdentity());
        }
    }

    protected void authenticationComplete(SecurityIdentity securityIdentity, String mechanism) {
        flexibleIdentityAssociation.setIdentity(securityIdentity);
        authenticationComplete(new ElytronAccount(securityIdentity), mechanism, false);
    }

    /**
     * @see io.undertow.security.api.SecurityContext#addAuthenticationMechanism(io.undertow.security.api.AuthenticationMechanism)
     */
    @Override
    public void addAuthenticationMechanism(AuthenticationMechanism mechanism) {
        throw new UnsupportedOperationException();
    }

    /**
     * @see io.undertow.security.api.SecurityContext#getAuthenticationMechanisms()
     */
    @Override
    public List<AuthenticationMechanism> getAuthenticationMechanisms() {
        throw new UnsupportedOperationException();
    }

    /**
     * @see io.undertow.security.api.SecurityContext#getIdentityManager()
     */
    @Override
    public IdentityManager getIdentityManager() {
        throw new UnsupportedOperationException();
    }

    FlexibleIdentityAssociation getFlexibleIdentityAssociation() {
        return flexibleIdentityAssociation;
    }

    static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        HttpServerExchange exchange;
        String programmaticMechanismName;
        SecurityDomain securityDomain;
        Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        ElytronHttpExchange httpExchange;
        AuthenticationMode authMode;
        Supplier<IdentityCache> identityCacheSupplier;

        protected Builder() {
        }

        Builder setExchange(HttpServerExchange exchange) {
            this.exchange = checkNotNullParam("exchange", exchange);

            return this;
        }

        @Deprecated
        Builder setProgramaticMechanismName(final String programmaticMechanismName) {
            return this.setProgrammaticMechanismName(programmaticMechanismName);
        }

        Builder setProgrammaticMechanismName(final String programmaticMechanismName) {
            this.programmaticMechanismName = programmaticMechanismName;

            return this;
        }

        public Builder setAuthMode(AuthenticationMode authMode) {
            this.authMode = authMode;
            return this;
        }

        Builder setSecurityDomain(final SecurityDomain securityDomain) {
            this.securityDomain = securityDomain;

            return this;
        }

        Builder setMechanismSupplier(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
            this.mechanismSupplier = checkNotNullParam("mechanismSupplier", mechanismSupplier);

            return this;
        }

        @Deprecated
        Builder setHttpExchangeSupplier(ElytronHttpExchange httpExchange) {
            return setHttpExchange(httpExchange);
        }

        Builder setHttpExchange(ElytronHttpExchange httpExchange) {
            this.httpExchange = checkNotNullParam("httpExchange", httpExchange);

            return this;
        }

        Builder setIdentityCacheSupplier(Supplier<IdentityCache> identityCacheSupplier) {
            this.identityCacheSupplier = identityCacheSupplier;

            return this;
        }

        public SecurityContext build() {
            return new SecurityContextImpl(this);
        }
    }
}
