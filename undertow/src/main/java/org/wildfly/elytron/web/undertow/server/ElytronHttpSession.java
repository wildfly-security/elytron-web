package org.wildfly.elytron.web.undertow.server;

import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;
import org.wildfly.security.http.HttpServerSession;
import org.wildfly.security.http.HttpSessionSpi;

import java.util.Set;

/**
 * Undertow specific implementation of {@link HttpSessionSpi}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronHttpSession implements HttpSessionSpi {

    private final HttpServerExchange exchange;

    public ElytronHttpSession(HttpServerExchange exchange) {
        this.exchange = exchange;
    }

    @Override
    public HttpServerSession getSession(boolean create) {
        SessionManager sessionManager = getSessionManager(exchange);
        SessionConfig sessionConfig = getSessionConfig(exchange);
        Session session = sessionManager.getSession(exchange, sessionConfig);

        if (create && session == null) {
            session = sessionManager.createSession(exchange, sessionConfig);
        }

        return createSession(session);
    }

    @Override
    public HttpServerSession getSession(String id) {
        SessionManager sessionManager = getSessionManager(exchange);
        Session session = sessionManager.getSession(id);

        return createSession(session);
    }

    @Override
    public Set<String> getSessions() {
        SessionManager sessionManager = getSessionManager(exchange);
        return sessionManager.getAllSessions();
    }

    protected SessionManager getSessionManager(HttpServerExchange exchange) {
        return exchange.getAttachment(SessionManager.ATTACHMENT_KEY);
    }

    protected SessionConfig getSessionConfig(HttpServerExchange exchange) {
        return exchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
    }

    private HttpServerSession createSession(Session session) {
        if (session == null) {
            return null;
        }

        return new HttpServerSession() {
            @Override
            public String getId() {
                return session.getId();
            }

            @Override
            public Object getAttribute(String name) {
                return session.getAttribute(name);
            }

            @Override
            public void setAttribute(String name, Object value) {
                session.setAttribute(name, value);
            }

            @Override
            public Object removeAttribute(String name) {
                return session.removeAttribute(name);
            }

            @Override
            public void invalidate() {
                session.invalidate(exchange);
            }
        };
    }
}
