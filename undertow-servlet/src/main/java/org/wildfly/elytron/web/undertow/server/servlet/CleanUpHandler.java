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

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

/**
 * A {@link HttpHandler} to call any {@link CleanUpTask} attached to the {@link HttpServerExchange}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CleanUpHandler implements HttpHandler {

    private final HttpHandler next;

    CleanUpHandler(final HttpHandler next) {
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        try {
            next.handleRequest(exchange);
        } finally {
            CleanUpTask cleanUpTask = exchange.getAttachment(CleanUpTask.ATTACHMENT_KEY);
            if (cleanUpTask != null) {
                cleanUpTask.cleanUp(exchange);
            }
        }
    }

}
