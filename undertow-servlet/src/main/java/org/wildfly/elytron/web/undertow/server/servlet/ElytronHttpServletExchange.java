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

import static org.wildfly.security.http.HttpConstants.OK;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;

import org.jboss.logging.Logger;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.elytron.web.undertow.server.ScopeSessionListener;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpScopeNotification;
import org.wildfly.security.http.Scope;

import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;
import io.undertow.servlet.api.Deployment;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.util.SavedRequest;

/**
 * An extension of {@link ElytronHttpExchange} which adds servlet container specific integrations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronHttpServletExchange extends ElytronHttpExchange {

    private static final Logger log = Logger.getLogger("org.wildfly.security.http.servlet");

    private final HttpServerExchange httpServerExchange;
    private final ScopeSessionListener scopeSessionListener;

    static Function<HttpServerExchange, HttpScope> APPLICATION_SCOPE_RESOLVER = ElytronHttpServletExchange::applicationScope;

    protected ElytronHttpServletExchange(final HttpServerExchange httpServerExchange, final ScopeSessionListener scopeSessionListener) {
        super(httpServerExchange);
        this.httpServerExchange = httpServerExchange;
        this.scopeSessionListener = scopeSessionListener;
    }

    @Override
    protected SessionManager getSessionManager() {
        ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        return servletRequestContext.getDeployment().getSessionManager();
    }

    @Override
    public Map<String, List<String>> getRequestParameters() {
        if (requestParameters == null) {
            synchronized (this) {
                ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                ServletRequest servletRequest = servletRequestContext.getServletRequest();
                if (servletRequest instanceof HttpServletRequest) {
                    HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                    Map<String, String[]> parameters = httpServletRequest.getParameterMap();
                    Map<String, List<String>> requestParameters = new HashMap<>(parameters.size());
                    for (Entry<String, String[]> entry : parameters.entrySet()) {
                        requestParameters.put(entry.getKey(), Collections.unmodifiableList(Arrays.asList(entry.getValue())));
                    }
                    this.requestParameters = Collections.unmodifiableMap(requestParameters);
                } else {
                    return super.getRequestParameters();
                }
            }
        }

        return requestParameters;
    }

    @Override
    protected SessionConfig getSessionConfig() {
        ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        return servletRequestContext.getCurrentServletContext().getSessionConfig();
    }

    @Override
    public int forward(String path) {
        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        ServletRequest req = servletRequestContext.getServletRequest();
        ServletResponse resp = servletRequestContext.getServletResponse();
        RequestDispatcher disp = req.getRequestDispatcher(path);
        if (disp == null) {
            return super.forward(path);
        }

        final FormResponseWrapper respWrapper = httpServerExchange.getStatusCode() != OK && resp instanceof HttpServletResponse
                ? new FormResponseWrapper((HttpServletResponse) resp) : null;

        try {
            disp.forward(req, respWrapper != null ? respWrapper : resp);
        } catch (ServletException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return respWrapper != null ? respWrapper.getStatus() : httpServerExchange.getStatusCode();
    }

    @Override
    public boolean suspendRequest() {
        SavedRequest.trySaveRequest(httpServerExchange);

        return true;
    }

    @Override
    public boolean resumeRequest() {
        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        HttpSession session = servletRequestContext.getCurrentServletContext().getSession(httpServerExchange, false);
        if (session != null) {
            SavedRequest.tryRestoreRequest(httpServerExchange, session);
        }

        return true;
    }

    @Override
    public HttpScope getScope(Scope scope) {
        switch (scope) {
            case APPLICATION:
                return applicationScope(httpServerExchange);
            case EXCHANGE:
                return requestScope(httpServerExchange);
            case SESSION:
                return sessionScope(httpServerExchange, scopeSessionListener);
            default:
                return super.getScope(scope);
        }
    }

    private static HttpScope applicationScope(HttpServerExchange exchange) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        if (servletRequestContext != null) {
            final Deployment deployment = servletRequestContext.getDeployment();
            final ServletContext servletContext = deployment.getServletContext();
            return new HttpScope() {
                @Override
                public String getID() {
                    return deployment.getDeploymentInfo().getDeploymentName();
                }

                @Override
                public boolean supportsAttachments() {
                    return true;
                }

                @Override
                public void setAttachment(String key, Object value) {
                    servletContext.setAttribute(key, value);
                }

                @Override
                public Object getAttachment(String key) {
                    return servletContext.getAttribute(key);
                }

                @Override
                public boolean supportsResources() {
                    return true;
                }

                @Override
                public InputStream getResource(String path) {
                    return servletContext.getResourceAsStream(path);
                }
            };
        }

        return null;
    }

    private static HttpScope requestScope(HttpServerExchange exchange) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        if (servletRequestContext != null) {
            final ServletRequest servletRequest = servletRequestContext.getServletRequest();
            return new HttpScope() {
                @Override
                public boolean supportsAttachments() {
                    return true;
                }

                @Override
                public void setAttachment(String key, Object value) {
                    servletRequest.setAttribute(key, value);
                }

                @Override
                public Object getAttachment(String key) {
                    return servletRequest.getAttribute(key);
                }

            };
        }

        return null;
    }

    private static HttpScope sessionScope(HttpServerExchange exchange, ScopeSessionListener listener) {
        ServletRequestContext context = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        return new HttpScope() {
            private HttpSession session = context.getOriginalRequest().getSession(false);

            @Override
            public String getID() {
                return (exists()) ? session.getId() : null;
            }

            @Override
            public boolean exists() {
                return session != null;
            }

            @Override
            public synchronized boolean create() {
                if (exists()) {
                    return false;
                }
                session = context.getOriginalRequest().getSession(true);
                return session != null;
            }

            @Override
            public boolean supportsAttachments() {
                return true;
            }

            @Override
            public void setAttachment(String key, Object value) {
                if (exists()) {
                    session.setAttribute(key, value);
                }
            }

            @Override
            public Object getAttachment(String key) {
                return (exists()) ? session.getAttribute(key) : null;
            }

            @Override
            public boolean supportsInvalidation() {
                return true;
            }

            @Override
            public boolean invalidate() {
                if (exists()) {
                    try {
                        session.invalidate();
                        return true;
                    } catch (IllegalStateException cause) {
                        // if session already invalidated we log a message and return false
                        log.debugf("Failed to invalidate session", cause);
                    }
                }
                return false;
            }

            @Override
            public boolean supportsNotifications() {
                return true;
            }

            @Override
            public void registerForNotification(Consumer<HttpScopeNotification> consumer) {
                if (exists()) {
                    listener.registerListener(session.getId(), consumer);
                }
            }
        };
    }

    private static class FormResponseWrapper extends HttpServletResponseWrapper {

        private int status = OK;

        private FormResponseWrapper(final HttpServletResponse wrapped) {
            super(wrapped);
        }

        @Override
        public void setStatus(int sc, String sm) {
            status = sc;
        }

        @Override
        public void setStatus(int sc) {
            status = sc;
        }

        @Override
        public int getStatus() {
            return status;
        }

    }

}
