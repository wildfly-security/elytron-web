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
package org.wildfly.elytron.web.undertow.server.util;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SessionInvalidationHandler implements HttpHandler {

    private final HttpHandler next;

    public SessionInvalidationHandler(HttpHandler next) {
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        if (exchange.getRequestPath().endsWith("/logout")) {
            SessionManager sessionManager = getSessionManager(exchange);
            if (sessionManager != null) {
                Session session = sessionManager.getSession(exchange, getSessionConfig(exchange));
                if (session != null) {
                    session.invalidate(exchange);
                    exchange.endExchange();
                }
            }
        } else {
            next.handleRequest(exchange);
        }
    }

    private SessionManager getSessionManager(HttpServerExchange exchange) {
        return exchange.getAttachment(SessionManager.ATTACHMENT_KEY);
    }

    private SessionConfig getSessionConfig(HttpServerExchange exchange) {
        return exchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
    }
}
