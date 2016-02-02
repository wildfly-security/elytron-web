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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.List;

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;

/**
 * Implementation of {@link HttpExchangeSpi} to wrap access to the Undertow specific {@link HttpServerExchange}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronHttpExchange implements HttpExchangeSpi {

    private final HttpServerExchange httpServerExchange;

    ElytronHttpExchange(final HttpServerExchange httpServerExchange) {
        this.httpServerExchange = checkNotNullParam("httpServerExchange", httpServerExchange);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestHeaderValues(java.lang.String)
     */
    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return httpServerExchange.getRequestHeaders().get(headerName);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#addResponseHeader(java.lang.String, java.lang.String)
     */
    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        httpServerExchange.getResponseHeaders().add(new HttpString(headerName), headerValue);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#setResponseCode(int)
     */
    @Override
    public void setResponseCode(int responseCode) {
        httpServerExchange.setResponseCode(responseCode);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationComplete(org.wildfly.security.auth.spi.AuthenticatedRealmIdentity, java.lang.String)
     */
    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        SecurityContext securityContext = httpServerExchange.getSecurityContext();
        if (securityContext != null) {
            securityContext.authenticationComplete(new ElytronAccount(securityIdentity), mechanismName, false);
        }
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationFailed(java.lang.String, java.lang.String)
     */
    @Override
    public void authenticationFailed(String message, String mechanismName) {
        SecurityContext securityContext = httpServerExchange.getSecurityContext();
        if (securityContext != null) {
            securityContext.authenticationFailed(message, mechanismName);
        }
    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {
    }

}
