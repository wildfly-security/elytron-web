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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpScopeNotification;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;
import org.xnio.SslClientAuthMode;

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.RenegotiationRequiredException;
import io.undertow.server.SSLSessionInfo;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.handlers.form.FormData;
import io.undertow.server.handlers.form.FormData.FormValue;
import io.undertow.server.handlers.form.FormDataParser;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;
import io.undertow.util.AbstractAttachable;
import io.undertow.util.AttachmentKey;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;

/**
 * Implementation of {@link HttpExchangeSpi} to wrap access to the Undertow specific {@link HttpServerExchange}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private static final AttachmentKey<HttpScope> HTTP_SCOPE_ATTACHMENT_KEY = AttachmentKey.create(HttpScope.class);
    private static final FormParserFactory FORM_PARSER_FACTORY = FormParserFactory.builder().build();

    private final HttpServerExchange httpServerExchange;
    private final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers;
    private final ScopeSessionListener scopeSessionListener;


    protected Map<String, List<String>> requestParameters;

    protected ElytronHttpExchange(final HttpServerExchange httpServerExchange,
            final Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers,
            final ScopeSessionListener scopeSessionListener) {
        this.httpServerExchange = checkNotNullParam("httpServerExchange", httpServerExchange);
        this.scopeResolvers = scopeResolvers;
        this.scopeSessionListener = scopeSessionListener;
    }

    protected ElytronHttpExchange(final HttpServerExchange httpServerExchange) {
        this(httpServerExchange, Collections.emptyMap(), null);
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
        HttpString headerString = Headers.fromCache(headerName);
        httpServerExchange.getResponseHeaders().add(headerString != null ? headerString : new HttpString(headerName),
                headerValue);
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#getSSLSession()
     */
    @Override
    public SSLSession getSSLSession() {
        SSLSessionInfo sessionInfo = httpServerExchange.getConnection().getSslSessionInfo();
        if (sessionInfo != null) {
            return sessionInfo.getSSLSession();
        }
        return null;
    }

    @Override
    public Certificate[] getPeerCertificates(boolean renegotiate) {
        SSLSessionInfo info = httpServerExchange.getConnection().getSslSessionInfo();
        if(info == null) {
            return null;
        }

        try {
            Certificate[] peerCertificates = info.getPeerCertificates();
            if (peerCertificates != null || renegotiate==false) return peerCertificates;
        } catch (SSLPeerUnverifiedException |RenegotiationRequiredException e) {}

        try {
            info.renegotiate(httpServerExchange, SslClientAuthMode.REQUESTED);
            return httpServerExchange.getConnection().getSslSessionInfo().getPeerCertificates();
        } catch (IOException | RenegotiationRequiredException e) {}

        return null;
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationComplete(SecurityIdentity, String)
     */
    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        SecurityContext securityContext = httpServerExchange.getSecurityContext();
        if (securityContext != null) {
            securityContext.authenticationComplete(new ElytronAccount(securityIdentity), mechanismName, false);
        }
    }

    /**
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationFailed(String, String)
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
    public URI getRequestURI() {
        final String scheme;
        final String host;
        final int port;
        final String path;
        final String query = httpServerExchange.getQueryString();
        try {
            if (httpServerExchange.isHostIncludedInRequestURI()) {
                URI tempUri = new URI(httpServerExchange.getRequestURI());
                scheme = tempUri.getScheme();
                host = tempUri.getHost();
                port = tempUri.getPort();
                path = tempUri.getPath();
            } else {
                scheme = httpServerExchange.getRequestScheme();
                host = httpServerExchange.getHostName();
                port = httpServerExchange.getHostPort();
                path = httpServerExchange.getRequestURI();
            }
            return new URI(scheme, null, host,
                    ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443) ? -1 : port, path,
                    query == null || "".equals(query) ? null : query, null);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    @Override
    public String getRequestPath() {
        return httpServerExchange.getRelativePath();
    }

    @Override
    public Map<String, List<String>> getRequestParameters() {
        if (requestParameters == null) {
            synchronized(this) {
                if (requestParameters == null) {
                    HashMap<String, List<String>> parameters = new HashMap<>();

                    Map<String, Deque<String>> queryParameters = httpServerExchange.getQueryParameters();

                    FormDataParser parser = FORM_PARSER_FACTORY.createParser(httpServerExchange);

                    if (parser != null) {
                        try {
                            FormData data = parser.parseBlocking();

                            for (Map.Entry<String, Deque<String>> queryParametersEntry : queryParameters.entrySet()) {
                                List<String> values = new ArrayList<>(queryParametersEntry.getValue());
                                if (data.contains(queryParametersEntry.getKey())) {
                                    Deque<FormValue> formValues = data.get(queryParametersEntry.getKey());
                                    formValues.stream().filter((FormValue fv) -> fv.isFile() == false)
                                            .forEach((FormValue fv) -> values.add(fv.getValue()));
                                }
                                parameters.put(queryParametersEntry.getKey(), Collections.unmodifiableList(values));
                            }

                            StreamSupport
                                    .stream(data.spliterator(), false)
                                    .filter((String s) -> parameters.containsKey(s) == false)
                                    .forEach(
                                            (String s) -> parameters.put(s,
                                                    Collections.unmodifiableList(data.get(s).stream()
                                                            .filter((FormValue v) -> v.isFile() == false)
                                                            .map((FormValue fv) -> fv.getValue()).collect(Collectors.toList()))));
                        } catch (IOException e) {}
                    } else {
                        queryParameters.forEach((name, values) -> parameters.put(name, Collections.unmodifiableList(new ArrayList<String>(values))));
                    }
                    requestParameters = Collections.unmodifiableMap(parameters);
                }
            }
        }

        return requestParameters;
    }

    @Override
    public List<HttpServerCookie> getCookies() {
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
        }).collect(Collectors.toList());
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
        return httpServerExchange.getOutputStream();
    }

    @Override
    public HttpScope getScope(Scope scope) {
        if (scopeResolvers.containsKey(scope)) {
            return scopeResolvers.get(scope).apply(httpServerExchange);
        }

        switch (scope) {
            case APPLICATION: {
                SessionManager sessionManager = getSessionManager();
                if (sessionManager == null) return null;

                return new HttpScope() {
                    @Override
                    public String getID() {
                        // TODO Find a better mechanism for obtaining a unique deployment ID
                        return sessionManager.getDeploymentName();
                    }
                };
            }
            case CONNECTION:
                return getScope(httpServerExchange.getConnection());
            case EXCHANGE:
                return getScope(httpServerExchange);
            case GLOBAL:
                return null;
            case SESSION:
                return toScope(null);
            case SSL_SESSION:
                return getScope(getSSLSession());
        }
        return null;
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        if (scope == Scope.SESSION) {
            SessionManager sessionManager = getSessionManager();
            return sessionManager.getAllSessions();
        }

        return null;
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        if (scope == Scope.SESSION) {
            return toScope(id);
        }
        return null;
    }

    @Override
    public void setStatusCode(int statusCode) {
        if (httpServerExchange.isResponseStarted() == false) {
            httpServerExchange.setStatusCode(statusCode);
        }
    }

    @Override
    public String getRemoteUser() {
        return httpServerExchange.getAttachment(HttpServerExchange.REMOTE_USER);
    }

    /**
     * Sub-types may override this method to define how {@link SessionManager} is obtained.
     *
     * @return the {@link SessionManager}
     */
    protected  SessionManager getSessionManager() {
        return httpServerExchange.getAttachment(SessionManager.ATTACHMENT_KEY);
    }

    /**
     * Sub-types may override this method to define how {@link SessionConfig} is obtained.
     *
     * @return the {@link SessionConfig}
     */
    protected SessionConfig getSessionConfig() {
        return httpServerExchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
    }

    private HttpScope toScope(String id) {
        SessionManager sessionManager = getSessionManager();
        SessionConfig sessionConfig = getSessionConfig();

        if (sessionManager == null || sessionConfig == null) {
            return null;
        }

        return new HttpScope() {

            private Session session = id == null ? sessionManager.getSession(httpServerExchange, sessionConfig) : sessionManager.getSession(id);

            @Override
            public String getID() {
                if (exists()) {
                    return session.getId();
                }
                return null;
            }

            @Override
            public boolean exists() {
                return session != null;
            }

            @Override
            public boolean create() {
                if (exists()) {
                    return false;
                }
                session = sessionManager.createSession(httpServerExchange, sessionConfig);
                return session != null;
            }

            @Override
            public boolean supportsAttachments() {
                return exists();
            }

            @Override
            public void setAttachment(String key, Object value) {
                if (supportsAttachments()) {
                    session.setAttribute(key, value);
                }
            }

            @Override
            public Object getAttachment(String key) {
                if (supportsAttachments()) {
                    return session.getAttribute(key);
                }
                return null;
            }

            @Override
            public boolean supportsInvalidation() {
                return exists();
            }

            @Override
            public boolean invalidate() {
                if (supportsInvalidation()) {
                    session.invalidate(httpServerExchange);
                    return true;
                }
                return false;
            }

            @Override
            public boolean supportsNotifications() {
                return exists() && scopeSessionListener != null;
            }

            @Override
            public void registerForNotification(Consumer<HttpScopeNotification> notificationConsumer) {
                if (supportsNotifications()) {
                    scopeSessionListener.registerListener(session.getId(), notificationConsumer);
                }
            }
        };
    }

    private HttpScope getScope(AbstractAttachable attachable) {
        HttpScope httpScope = attachable.getAttachment(HTTP_SCOPE_ATTACHMENT_KEY);
        if (httpScope == null) {
            synchronized (attachable) {
                httpScope = attachable.getAttachment(HTTP_SCOPE_ATTACHMENT_KEY);
                if (httpScope == null) {
                    final Map<String, Object> storageMap = new HashMap<>();
                    httpScope = new HttpScope() {

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
                        public void setAttachment(String key, Object value) {
                            if (value != null) {
                                storageMap.put(key, value);
                            } else {
                                storageMap.remove(key);
                            }
                        }

                        @Override
                        public Object getAttachment(String key) {
                            return storageMap.get(key);
                        }

                    };

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
            public void setAttachment(String key, Object value) {
                sslSession.putValue(key, value);
            }

            @Override
            public Object getAttachment(String key) {
                return sslSession.getValue(key);
            }

        };


    }

}
