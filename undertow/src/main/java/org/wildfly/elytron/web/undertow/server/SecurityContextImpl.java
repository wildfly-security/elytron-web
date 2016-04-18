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
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.Scope;

import io.undertow.security.api.AuthenticationMechanism;
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

    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers;
    private final ScopeSessionListener scopeSessionListener;

    private SecurityContextImpl(Builder builder) {
        super(checkNotNullParam("exchange", builder.exchange));
        this.mechanismSupplier = checkNotNullParam("mechanismSupplier", builder.mechanismSupplier);
        this.scopeResolvers = builder.scopeResolvers;
        this.scopeSessionListener = builder.scopeSessionListener;
    }

    /**
     * @see io.undertow.security.api.SecurityContext#authenticate()
     */
    @Override
    public boolean authenticate() {
        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(mechanismSupplier)
                .setHttpExchangeSpi(new ElytronHttpExchange(exchange, scopeResolvers, scopeSessionListener))
                .setRequired(isAuthenticationRequired())
                .setIgnoreOptionalFailures(false) // TODO - Cover this one later.
                .build();

        try {
            return authenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            exchange.setResponseCode(INTERNAL_SERVER_ERROR);

            return false;
        }
    }

    /**
     * @see io.undertow.security.api.SecurityContext#login(java.lang.String, java.lang.String)
     */
    @Override
    public boolean login(String username, String password) {
        return false;
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

    static Builder builder() {
        return new Builder();
    }

    static class Builder {

        HttpServerExchange exchange;
        Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers;
        ScopeSessionListener scopeSessionListener;

        private Builder() {
        }

        Builder setExchange(HttpServerExchange exchange) {
            this.exchange = exchange;

            return this;
        }

        Builder setMechanismSupplier(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
            this.mechanismSupplier = mechanismSupplier;

            return this;
        }

        Builder setScopeResolvers(Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers) {
            this.scopeResolvers = scopeResolvers;

            return this;
        }

        Builder setScopeSessionListener(ScopeSessionListener scopeSessionListener) {
            this.scopeSessionListener = scopeSessionListener;

            return this;
        }

        SecurityContext build() {
            return new SecurityContextImpl(this);
        }
    }
}
