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

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderMap;
import io.undertow.util.HttpString;

/**
 * A simple {@link HttpHandler} for use when testing security, this handler is the end handler after
 * all security checks have been performed.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ResponseHandler implements HttpHandler {

    static final HttpString PROCESSED_BY = new HttpString("ProcessedBy");
    static final HttpString AUTHENTICATED_USER = new HttpString("AuthenticatedUser");

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        HeaderMap responseHeader = exchange.getResponseHeaders();
        responseHeader.add(PROCESSED_BY, "ResponseHandler");
        String user = getAuthenticatedUser(exchange);
        if (user != null) {
            responseHeader.add(AUTHENTICATED_USER, user);
        }
        if (exchange.getQueryParameters().get("logout") != null) {
            exchange.getSecurityContext().logout();
        }

        exchange.endExchange();
    }

    private String getAuthenticatedUser(final HttpServerExchange exchange) {
        SecurityContext context = exchange.getSecurityContext();
        if (context != null) {
            Account account = context.getAuthenticatedAccount();
            if (account != null) {
                // An account must always return a Principal otherwise it is not an Account.
                return account.getPrincipal().getName();
            }
        }

        return null;
    }

}
