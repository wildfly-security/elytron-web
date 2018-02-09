/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpScopeNotification;
import org.wildfly.security.http.Scope;

import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionListener;

/**
 * A {@link SessionListener} that handles notification so that they can be passed to the consumers registered to listen for
 * destruction of {@link HttpScope} instances of {@link Scope.SESSION}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ScopeSessionListener implements SessionListener {

    private final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers;
    private final Map<String, List<Consumer<HttpScopeNotification>>> registeredListeners = new HashMap<>();

    private ScopeSessionListener(Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers) {
        this.scopeResolvers = scopeResolvers;
    }

    public void registerListener(String sessionId, Consumer<HttpScopeNotification> notificationConsumer) {
        synchronized (this) {
            List<Consumer<HttpScopeNotification>> consumersForSession;
            if (registeredListeners.containsKey(sessionId)) {
                consumersForSession = registeredListeners.get(sessionId);
            } else {
                consumersForSession = new ArrayList<>();
                registeredListeners.put(sessionId, consumersForSession);
            }
            consumersForSession.add(notificationConsumer);
        }
    }

    @Override
    public synchronized void sessionIdChanged(Session session, String oldSessionId) {
        if (registeredListeners.containsKey(oldSessionId)) {
            List<Consumer<HttpScopeNotification>> consumersForSession = registeredListeners.remove(oldSessionId);
            registeredListeners.put(session.getId(), consumersForSession);
        }
    }

    @Override
    public synchronized void sessionDestroyed(final Session session, final HttpServerExchange exchange, SessionDestroyedReason reason) {
        List<Consumer<HttpScopeNotification>> consumersForSession = registeredListeners.remove(session.getId());
        if (consumersForSession == null) {
            return;
        }

        HttpScopeNotification scopeNotification = new HttpScopeNotification() {
            @Override
            public boolean isOfType(Enum... notification) {
                for (Enum type : notification) {
                    if (SessionNotificationType.INVALIDATED.equals(type) && SessionDestroyedReason.INVALIDATED.equals(reason)) {
                        return true;
                    }
                    if (SessionNotificationType.TIMEOUT.equals(type) && SessionDestroyedReason.TIMEOUT.equals(reason)) {
                        return true;
                    }
                    if (SessionNotificationType.UNDEPLOY.equals(type) && SessionDestroyedReason.UNDEPLOY.equals(reason)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public HttpScope getScope(Scope scope) {
                if (scopeResolvers.containsKey(scope)) {
                    return scopeResolvers.get(scope).apply(exchange);
                }

                if (scope == Scope.SESSION) {
                    return new HttpScope() {

                        @Override
                        public boolean exists() {
                            return true;
                        }

                        @Override
                        public boolean create() {
                            return false;
                        }

                        @Override
                        public boolean supportsAttachments() {
                            return true;
                        }

                        @Override
                        public boolean supportsInvalidation() {
                            return false;
                        }

                        @Override
                        public void setAttachment(String key, Object value) {
                            session.setAttribute(key, value);
                        }

                        @Override
                        public Object getAttachment(String key) {
                            return session.getAttribute(key);
                        }

                    };
                }

                return null;
            }

            @Override
            public Collection<String> getScopeIds(Scope scope) {
                return null;
            }

            @Override
            public HttpScope getScope(Scope scope, String id) {
                return null;
            }
        };

        for (Consumer<HttpScopeNotification> consumer : consumersForSession) {
            consumer.accept(scopeNotification);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers = new HashMap<>();

        private Builder() {
        }

        public Builder addScopeResolver(Scope scope, Function<HttpServerExchange, HttpScope> scopeResolver) {
            scopeResolvers.put(scope, scopeResolver);

            return this;
        }

        public ScopeSessionListener build() {
            return new ScopeSessionListener(scopeResolvers);
        }
    }
    /*
     * The following events are of no interest as we are only notifying on destruction.
     */

    @Override
    public void sessionCreated(Session session, HttpServerExchange exchange) {
    }

    @Override
    public void attributeAdded(Session session, String name, Object value) {
    }

    @Override
    public void attributeUpdated(Session session, String name, Object newValue, Object oldValue) {
    }

    @Override
    public void attributeRemoved(Session session, String name, Object oldValue) {
    }



}
