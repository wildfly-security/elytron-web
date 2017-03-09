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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.function.Supplier;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.Scope;
import org.wildfly.security.manager.WildFlySecurityManager;

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

    private static final String AUTHENTICATED_PRINCIPAL_KEY = SecurityContextImpl.class.getName() + ".authenticated-principal";

    private final String programaticMechanismName;
    private final SecurityDomain securityDomain;
    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final ElytronHttpExchange httpExchange;
    private Runnable logoutHandler;

    private SecurityContextImpl(Builder builder) {
        super(checkNotNullParam("exchange", builder.exchange));
        this.programaticMechanismName = checkNotNullParam("programaticMechanismName", builder.programaticMechanismName);
        this.securityDomain = builder.securityDomain;
        this.mechanismSupplier = checkNotNullParam("mechanismSupplier", builder.mechanismSupplier);
        this.httpExchange = checkNotNullParam("httpExchange", builder.httpExchange);
    }

    /**
     * @see io.undertow.security.api.SecurityContext#authenticate()
     */
    @Override
    public boolean authenticate() {
        if(isAuthenticated()) {
            return true;
        }
        if (restoreIdentity()) {
            return true;
        }

        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(mechanismSupplier)
                .setHttpExchangeSpi(this.httpExchange)
                .setRequired(isAuthenticationRequired())
                .setIgnoreOptionalFailures(false) // TODO - Cover this one later.
                .registerLogoutHandler(this::setLogoutHandler)
                .build();

        try {
            return authenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            exchange.setStatusCode(INTERNAL_SERVER_ERROR);

            return false;
        }
    }

    private void setLogoutHandler(Runnable runnable) {
        this.logoutHandler = runnable;
    }

    /**
     * @see io.undertow.security.api.SecurityContext#login(java.lang.String, java.lang.String)
     */
    @Override
    public boolean login(String username, String password) {
        if (securityDomain == null) {
            return false;
        }

        ServerAuthenticationContext authenticationContext;
        if(WildFlySecurityManager.isChecking()) {
            authenticationContext = AccessController.doPrivileged((PrivilegedAction<ServerAuthenticationContext>) () -> securityDomain.createNewAuthenticationContext());
        } else {
            authenticationContext = securityDomain.createNewAuthenticationContext();
        }

        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password.toCharArray());

        try {
            authenticationContext.setAuthenticationName(username);
            if (authenticationContext.verifyEvidence(evidence)) {
                if (authenticationContext.authorize()) {
                    SecurityIdentity authorizedIdentity = authenticationContext.getAuthorizedIdentity();
                    HttpScope sessionScope = httpExchange.getScope(Scope.SESSION);
                    if (sessionScope != null && sessionScope.supportsAttachments()) {
                        sessionScope.setAttachment(AUTHENTICATED_PRINCIPAL_KEY, username);
                    }
                    setupProgramaticLogout(sessionScope);

                    authenticationComplete(new ElytronAccount(authorizedIdentity), programaticMechanismName, false);

                    return true;
                } else {
                    authenticationFailed("Authorization Failed", programaticMechanismName);
                }
            } else {
                authenticationFailed("Authentication Failed", programaticMechanismName);
            }
        } catch (IllegalArgumentException | RealmUnavailableException | IllegalStateException e) {
            authenticationFailed(e.getMessage(), programaticMechanismName);
        } finally {
            evidence.destroy();
        }

        return false;
    }

    @Override
    public void logout() {
        super.logout();
        if (logoutHandler != null) {
            logoutHandler.run();
        }
    }

    private boolean restoreIdentity() {
        if (securityDomain == null) {
            return false;
        }

        HttpScope sessionScope = httpExchange.getScope(Scope.SESSION);
        if (sessionScope != null && sessionScope.supportsAttachments()) {
            String principalName = sessionScope.getAttachment(AUTHENTICATED_PRINCIPAL_KEY, String.class);
            if (principalName != null) {
                ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();
                try {
                    authenticationContext.setAuthenticationName(principalName);
                    if (authenticationContext.authorize()) {
                        SecurityIdentity authorizedIdentity = authenticationContext.getAuthorizedIdentity();
                        authenticationComplete(new ElytronAccount(authorizedIdentity), programaticMechanismName, false);
                        setupProgramaticLogout(sessionScope);

                        return true;
                    } else {
                        sessionScope.setAttachment(AUTHENTICATED_PRINCIPAL_KEY, null); // Whatever was in there no longer works so just drop it.
                    }
                } catch (IllegalArgumentException | RealmUnavailableException | IllegalStateException e) {
                    authenticationFailed(e.getMessage(), programaticMechanismName);
                }
            }
        }

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

    private void setupProgramaticLogout(HttpScope sessionScope) {
        logoutHandler = () -> {
            sessionScope.setAttachment(AUTHENTICATED_PRINCIPAL_KEY, null);
        };
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {

        HttpServerExchange exchange;
        String programaticMechanismName;
        SecurityDomain securityDomain;
        Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
        ElytronHttpExchange httpExchange;

        private Builder() {
        }

        Builder setExchange(HttpServerExchange exchange) {
            this.exchange = exchange;

            return this;
        }

        Builder setProgramaticMechanismName(final String programaticMechanismName) {
            this.programaticMechanismName = programaticMechanismName;

            return this;
        }

        Builder setSecurityDomain(final SecurityDomain securityDomain) {
            this.securityDomain = securityDomain;

            return this;
        }

        Builder setMechanismSupplier(Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier) {
            this.mechanismSupplier = mechanismSupplier;

            return this;
        }

        Builder setHttpExchangeSupplier(ElytronHttpExchange httpExchange) {
            this.httpExchange = httpExchange;

            return this;
        }

        SecurityContext build() {
            return new SecurityContextImpl(this);
        }
    }
}
