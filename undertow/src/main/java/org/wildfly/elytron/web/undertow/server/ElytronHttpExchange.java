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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.net.ssl.SSLSession;

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.ServerConnection;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.protocol.http.HttpServerConnection;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;
import io.undertow.util.AbstractAttachable;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HttpString;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;

/**
 * Implementation of {@link HttpExchangeSpi} to wrap access to the Undertow specific {@link HttpServerExchange}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronHttpExchange implements HttpExchangeSpi {

    private static final AttachmentKey<HttpScope> HTTP_SCOPE_ATTACHMENT_KEY = AttachmentKey.create(HttpScope.class);

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
     * @see org.wildfly.security.http.HttpExchangeSpi#getSSLSession()
     */
    @Override
    public SSLSession getSSLSession() {
        ServerConnection connection = httpServerExchange.getConnection();
        if (connection instanceof HttpServerConnection) {
            return ((HttpServerConnection) connection).getSslSession();
        }
        return null;
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

    @Override
    public String getRequestMethod() {
        return httpServerExchange.getRequestMethod().toString();
    }

    @Override
    public String getRequestURI() {
        StringBuilder uriBuilder = new StringBuilder();

        if (!httpServerExchange.isHostIncludedInRequestURI()) {
            uriBuilder.append(httpServerExchange.getRequestScheme()).append("://").append(httpServerExchange.getHostAndPort());
        }

        uriBuilder.append(httpServerExchange.getRequestURI());

        String queryString = httpServerExchange.getQueryString();

        if (queryString != null && !"".equals(queryString.trim())) {
            uriBuilder.append("?").append(queryString);
        }

        return uriBuilder.toString();
    }

    @Override
    public Map<String, String[]> getRequestParameters() {
        HashMap<String, String[]> parameters = new HashMap<>();
        Map<String, Deque<String>> queryParameters = httpServerExchange.getQueryParameters();

        queryParameters.forEach((name, values) -> parameters.put(name, values.toArray(new String[values.size()])));

        return parameters;
    }

    @Override
    public HttpServerCookie[] getCookies() {
        Map<String, Cookie> cookies = httpServerExchange.getRequestCookies();
        return cookies.values().stream().map((Function<Cookie, HttpServerCookie>) cookie -> new HttpServerCookie() {
            @Override
            public String getName() {
                return cookie.getName();
            }

            @Override
            public String getValue() {
                return cookie.getValue();
            }

            @Override
            public String getDomain() {
                return cookie.getDomain();
            }

            @Override
            public int getMaxAge() {
                return cookie.getMaxAge();
            }

            @Override
            public String getPath() {
                return cookie.getPath();
            }

            @Override
            public boolean isSecure() {
                return cookie.isSecure();
            }

            @Override
            public int getVersion() {
                return cookie.getVersion();
            }

            @Override
            public boolean isHttpOnly() {
                return cookie.isHttpOnly();
            }
        }).collect(Collectors.toList()).toArray(new HttpServerCookie[cookies.size()]);
    }

    @Override
    public InputStream getRequestInputStream() {
        return httpServerExchange.getInputStream();
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return httpServerExchange.getSourceAddress();
    }

    @Override
    public void setResponseCookie(HttpServerCookie cookie) {
        CookieImpl actualCookie = new CookieImpl(cookie.getName(), cookie.getValue());

        actualCookie.setDomain(cookie.getDomain());
        actualCookie.setMaxAge(cookie.getMaxAge());
        actualCookie.setHttpOnly(cookie.isHttpOnly());
        actualCookie.setSecure(cookie.isSecure());
        actualCookie.setPath(cookie.getPath());

        httpServerExchange.setResponseCookie(actualCookie);
    }

    @Override
    public OutputStream getResponseOutputStream() {
        return null;
    }

    @Override
    public HttpScope getScope(Scope scope) {
        switch (scope) {
            case APPLICATION:
                return null;
            case CONNECTION:
                return getScope(httpServerExchange.getConnection());
            case EXCHANGE:
                return getScope(httpServerExchange);
            case GLOBAL:
                return null;
            case SESSION:
                SessionManager sessionManager = httpServerExchange.getAttachment(SessionManager.ATTACHMENT_KEY);
                SessionConfig sessionConfig = httpServerExchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
                Session session = sessionManager.getSession(httpServerExchange, sessionConfig);
                if (session == null) {
                    session = sessionManager.createSession(httpServerExchange, sessionConfig);
                }

                final Session finalSession = session;
                return new WrapperScope(session::getAttribute, session::setAttribute, () -> {
                    finalSession.invalidate(httpServerExchange);
                    return true;
                });
            case SSL_SESSION:
                return getScope(getSSLSession());
        }
        return null; // Unreachable
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        if (scope == Scope.SESSION) {
            SessionManager sessionManager = httpServerExchange.getAttachment(SessionManager.ATTACHMENT_KEY);
            return sessionManager.getAllSessions();
        }

        return null;
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        if (scope == Scope.SESSION) {
            SessionManager sessionManager = httpServerExchange.getAttachment(SessionManager.ATTACHMENT_KEY);
            Session session = sessionManager.getSession(id);
            if (session != null) {
                return new WrapperScope(session::getAttribute, session::setAttribute, () -> {
                    session.invalidate(httpServerExchange);
                    return true;
                });
            }
        }
        return null;
    }

    private HttpScope getScope(AbstractAttachable attachable) {
        HttpScope httpScope = attachable.getAttachment(HTTP_SCOPE_ATTACHMENT_KEY);
        if (httpScope == null) {
            synchronized (attachable) {
                httpScope = attachable.getAttachment(HTTP_SCOPE_ATTACHMENT_KEY);
                if (httpScope == null) {
                    httpScope = new MapBackedScope(new HashMap<>());
                    attachable.putAttachment(HTTP_SCOPE_ATTACHMENT_KEY, httpScope);
                }
            }
        }

        return httpScope;
    }

    private HttpScope getScope(final SSLSession sslSession) {
        if (sslSession == null) {
            return null;
        }

        return new WrapperScope(sslSession::getValue, sslSession::putValue);
    }

    private class WrapperScope implements HttpScope {

        private final Function<String, Object> getter;
        private final BiConsumer<String, Object> putter;
        private final BooleanSupplier invalidator;

        WrapperScope(Function<String, Object> getter, BiConsumer<String, Object> putter, BooleanSupplier invalidator) {
            this.getter = getter;
            this.putter = putter;
            this.invalidator = invalidator;
        }

        WrapperScope(Function<String, Object> getter, BiConsumer<String, Object> putter) {
            this(getter, putter, null);
        }
        @Override
        public boolean supportsAttachments() {
            return true;
        }

        @Override
        public void setAttachment(String key, Object value) {
            putter.accept(key, value);
        }

        @Override
        public Object getAttachment(String key) {
            return getter.apply(key);
        }

        @Override
        public boolean supportsInvalidation() {
            return invalidator != null;
        }

        @Override
        public boolean invalidate() {
            return invalidator.getAsBoolean();
        }

    }


    private class MapBackedScope implements HttpScope {

        private final Map<String, Object> attachmentMap;

        MapBackedScope(Map<String, Object> attachmentMap) {
            this.attachmentMap = attachmentMap;
        }

        @Override
        public boolean supportsAttachments() {
            return true;
        }

        @Override
        public void setAttachment(String key, Object value) {
            if (value != null) {
                attachmentMap.put(key, value);
            } else {
                attachmentMap.remove(key);
            }
        }

        @Override
        public Object getAttachment(String key) {

            return HttpScope.super.getAttachment(key);
        }


    }


}
