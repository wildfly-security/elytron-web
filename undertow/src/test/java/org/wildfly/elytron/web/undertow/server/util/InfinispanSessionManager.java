package org.wildfly.elytron.web.undertow.server.util;

import io.undertow.UndertowLogger;
import io.undertow.UndertowMessages;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.SecureRandomSessionIdGenerator;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionIdGenerator;
import io.undertow.server.session.SessionListener;
import io.undertow.server.session.SessionListeners;
import io.undertow.server.session.SessionManager;
import io.undertow.server.session.SessionManagerStatistics;
import io.undertow.util.AttachmentKey;
import io.undertow.util.ConcurrentDirectDeque;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.xnio.XnioExecutor;
import org.xnio.XnioIoThread;
import org.xnio.XnioWorker;

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.MathContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/**
 * A modified version of {@link io.undertow.server.session.InMemorySessionManager} using a Infinispan distributable cache.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class InfinispanSessionManager implements SessionManager, SessionManagerStatistics {

    private final AttachmentKey<SessionImpl> NEW_SESSION = AttachmentKey.create(SessionImpl.class);

    private final SessionIdGenerator sessionIdGenerator;

    private ConcurrentMap<String, SessionImpl> sessions;

    private final SessionListeners sessionListeners = new SessionListeners();

    /**
     * 30 minute default
     */
    private volatile int defaultSessionTimeout = 30 * 60;

    private final int maxSize;

    private final ConcurrentDirectDeque<String> evictionQueue;

    private final String deploymentName;

    private final AtomicLong createdSessionCount = new AtomicLong();
    private final AtomicLong expiredSessionCount = new AtomicLong();
    private final AtomicLong rejectedSessionCount = new AtomicLong();
    private final AtomicLong averageSessionLifetime = new AtomicLong();
    private final AtomicLong longestSessionLifetime = new AtomicLong();
    private final boolean statisticsEnabled;

    private volatile long startTime;

    private final boolean expireOldestUnusedSessionOnMax;
    private EmbeddedCacheManager cacheManager;


    public InfinispanSessionManager(String deploymentName, int maxSessions, boolean expireOldestUnusedSessionOnMax) {
        this(new SecureRandomSessionIdGenerator(), deploymentName, maxSessions, expireOldestUnusedSessionOnMax);
    }

    public InfinispanSessionManager(SessionIdGenerator sessionIdGenerator, String deploymentName, int maxSessions, boolean expireOldestUnusedSessionOnMax) {
        this(sessionIdGenerator, deploymentName, maxSessions, expireOldestUnusedSessionOnMax, true);
    }

    public InfinispanSessionManager(SessionIdGenerator sessionIdGenerator, String deploymentName, int maxSessions, boolean expireOldestUnusedSessionOnMax, boolean statisticsEnabled) {
        this.sessionIdGenerator = sessionIdGenerator;
        this.deploymentName = deploymentName;
        this.statisticsEnabled = statisticsEnabled;
        this.expireOldestUnusedSessionOnMax = expireOldestUnusedSessionOnMax;
        this.maxSize = maxSessions;
        ConcurrentDirectDeque<String> evictionQueue = null;
        if (maxSessions > 0) {
            evictionQueue = ConcurrentDirectDeque.newInstance();
        }
        this.evictionQueue = evictionQueue;
    }

    public InfinispanSessionManager(String deploymentName, int maxSessions) {
        this(deploymentName, maxSessions, false);
    }

    public InfinispanSessionManager(String id) {
        this(id, -1);
    }

    @Override
    public String getDeploymentName() {
        return this.deploymentName;
    }

    @Override
    public void start() {
        createdSessionCount.set(0);
        expiredSessionCount.set(0);
        this.cacheManager = new DefaultCacheManager(
                GlobalConfigurationBuilder.defaultClusteredBuilder()
                        .globalJmxStatistics().cacheManagerName(deploymentName)
                        .transport().nodeName(deploymentName).clusterName("default-cluster")
                        .build(),
                new ConfigurationBuilder()
                        .clustering()
                        .cacheMode(CacheMode.REPL_SYNC)
                        .build()
        );
        this.sessions = cacheManager.getCache();
        startTime = System.currentTimeMillis();
    }

    @Override
    public void stop() {
        for (Map.Entry<String, SessionImpl> session : sessions.entrySet()) {
            session.getValue().destroy();
            sessionListeners.sessionDestroyed(session.getValue(), null, SessionListener.SessionDestroyedReason.UNDEPLOY);
        }
        sessions.clear();
        this.cacheManager.stop();
    }

    @Override
    public Session createSession(final HttpServerExchange serverExchange, final SessionConfig config) {
        if (evictionQueue != null) {
            if(expireOldestUnusedSessionOnMax) {
                while (sessions.size() >= maxSize && !evictionQueue.isEmpty()) {

                    String key = evictionQueue.poll();
                    UndertowLogger.REQUEST_LOGGER.debugf("Removing session %s as max size has been hit", key);
                    SessionImpl toRemove = sessions.get(key);
                    if (toRemove != null) {
                        toRemove.invalidate(null, SessionListener.SessionDestroyedReason.TIMEOUT); //todo: better reason
                    }
                }
            } else if(sessions.size() >= maxSize) {
                if(statisticsEnabled) {
                    rejectedSessionCount.incrementAndGet();
                }
                throw UndertowMessages.MESSAGES.tooManySessions(maxSize);
            }
        }
        if (config == null) {
            throw UndertowMessages.MESSAGES.couldNotFindSessionCookieConfig();
        }
        String sessionID = config.findSessionId(serverExchange);
        int count = 0;
        while (sessionID == null) {
            sessionID = sessionIdGenerator.createSessionId();
            if(sessions.containsKey(sessionID)) {
                sessionID = null;
            }
            if(count++ == 100) {
                //this should never happen
                //but we guard against pathalogical session id generators to prevent an infinite loop
                throw UndertowMessages.MESSAGES.couldNotGenerateUniqueSessionId();
            }
        }
        Object evictionToken;
        if (evictionQueue != null) {
            evictionToken = evictionQueue.offerLastAndReturnToken(sessionID);
        } else {
            evictionToken = null;
        }
        if(statisticsEnabled) {
            createdSessionCount.incrementAndGet();
        }
        final SessionImpl session;
        if (sessions.containsKey(sessionID)) {
            SessionImpl session1 = sessions.get(sessionID);
            session = new SessionImpl(this, session1.sessionId, config, serverExchange.getIoThread(), serverExchange.getConnection().getWorker(), session1.evictionToken, defaultSessionTimeout, session1.attributes);
        } else {
            session = new SessionImpl(this, sessionID, config, serverExchange.getIoThread(), serverExchange.getConnection().getWorker(), evictionToken, defaultSessionTimeout);
        }
        sessions.put(sessionID, session);
        config.setSessionId(serverExchange, session.getId());
        session.lastAccessed = System.currentTimeMillis();
        session.bumpTimeout();
        sessionListeners.sessionCreated(session, serverExchange);
        serverExchange.putAttachment(NEW_SESSION, session);
        return session;
    }

    @Override
    public Session getSession(final HttpServerExchange serverExchange, final SessionConfig config) {
        if (serverExchange != null) {
            SessionImpl newSession = serverExchange.getAttachment(NEW_SESSION);
            if(newSession != null) {
                return newSession;
            }
        }
        String sessionId = config.findSessionId(serverExchange);
        Session session = getSession(sessionId);
        if (session == null && sessionId != null && sessions.containsKey(sessionId)) {
            SessionImpl session1 = sessions.get(sessionId);
            return new SessionImpl(this, sessionId, config, serverExchange.getIoThread(), serverExchange.getConnection().getWorker(), session1.evictionToken, defaultSessionTimeout, session1.attributes);
        }
        return session;
    }

    @Override
    public Session getSession(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        final SessionImpl sess = sessions.get(sessionId);
        if (sess == null || sess.sessionManager == null) {
            return null;
        } else {
            return sess;
        }
    }


    @Override
    public synchronized void registerSessionListener(final SessionListener listener) {
        sessionListeners.addSessionListener(listener);
    }

    @Override
    public synchronized void removeSessionListener(final SessionListener listener) {
        sessionListeners.removeSessionListener(listener);
    }

    @Override
    public void setDefaultSessionTimeout(final int timeout) {
        defaultSessionTimeout = timeout;
    }

    @Override
    public Set<String> getTransientSessions() {
        return getAllSessions();
    }

    @Override
    public Set<String> getActiveSessions() {
        return getAllSessions();
    }

    @Override
    public Set<String> getAllSessions() {
        return new HashSet<>(sessions.keySet());
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof SessionManager)) return false;
        SessionManager manager = (SessionManager) object;
        return this.deploymentName.equals(manager.getDeploymentName());
    }

    @Override
    public int hashCode() {
        return this.deploymentName.hashCode();
    }

    @Override
    public String toString() {
        return this.deploymentName;
    }

    @Override
    public SessionManagerStatistics getStatistics() {
        return this;
    }

    public long getCreatedSessionCount() {
        return createdSessionCount.get();
    }

    @Override
    public long getMaxActiveSessions() {
        return maxSize;
    }

    @Override
    public long getActiveSessionCount() {
        return sessions.size();
    }

    @Override
    public long getExpiredSessionCount() {
        return expiredSessionCount.get();
    }

    @Override
    public long getRejectedSessions() {
        return rejectedSessionCount.get();

    }

    @Override
    public long getMaxSessionAliveTime() {
        return longestSessionLifetime.get();
    }

    @Override
    public long getAverageSessionAliveTime() {
        return averageSessionLifetime.get();
    }

    @Override
    public long getStartTime() {
        return startTime;
    }


    /**
     * session implementation for the in memory session manager
     */
    private static class SessionImpl implements Session, Serializable {


        final transient InfinispanSessionManager sessionManager;
        ConcurrentMap<String, Object> attributes;
        volatile long lastAccessed;
        final long creationTime;
        volatile int maxInactiveInterval;

        static volatile AtomicReferenceFieldUpdater<SessionImpl, Object> evictionTokenUpdater;
        static {
            //this is needed in case there is unprivileged code on the stack
            //it needs to delegate to the createTokenUpdater() method otherwise the creation will fail
            //as the inner class cannot access the member
            evictionTokenUpdater = AccessController.doPrivileged(new PrivilegedAction<AtomicReferenceFieldUpdater<SessionImpl, Object>>() {
                @Override
                public AtomicReferenceFieldUpdater<SessionImpl, Object> run() {
                    return createTokenUpdater();
                }
            });
        }

        private static AtomicReferenceFieldUpdater<SessionImpl, Object> createTokenUpdater() {
            return AtomicReferenceFieldUpdater.newUpdater(SessionImpl.class, Object.class, "evictionToken");
        }


        private String sessionId;
        private volatile Object evictionToken;
        private final transient SessionConfig sessionCookieConfig;
        private volatile long expireTime = -1;
        private volatile boolean invalid = false;
        private volatile boolean invalidationStarted = false;

        final transient XnioExecutor executor;
        final transient XnioWorker worker;

        transient XnioExecutor.Key timerCancelKey;

        transient Runnable cancelTask = new Runnable() {
            @Override
            public void run() {
                worker.execute(new Runnable() {
                    @Override
                    public void run() {
                        long currentTime = System.currentTimeMillis();
                        if(currentTime >= expireTime) {
                            invalidate(null, SessionListener.SessionDestroyedReason.TIMEOUT);
                        } else {
                            timerCancelKey = executor.executeAfter(cancelTask, expireTime - currentTime, TimeUnit.MILLISECONDS);
                        }
                    }
                });
            }
        };

        private SessionImpl(InfinispanSessionManager infinispanSessionManager, String sessionId, SessionConfig config, XnioIoThread ioThread, XnioWorker worker, Object evictionToken, int defaultSessionTimeout) {
            this(infinispanSessionManager, sessionId, config, ioThread, worker, evictionToken, defaultSessionTimeout, new ConcurrentHashMap<>());
        }

        private SessionImpl(final InfinispanSessionManager sessionManager, final String sessionId, final SessionConfig sessionCookieConfig, final XnioExecutor executor, final XnioWorker worker, final Object evictionToken, final int maxInactiveInterval, ConcurrentMap<String, Object> attributes) {
            this.sessionManager = sessionManager;
            this.sessionId = sessionId;
            this.sessionCookieConfig = sessionCookieConfig;
            this.executor = executor;
            this.worker = worker;
            this.evictionToken = evictionToken;
            creationTime = lastAccessed = System.currentTimeMillis();
            this.maxInactiveInterval = maxInactiveInterval;
            this.attributes = attributes;
        }

        synchronized void bumpTimeout() {
            if(invalidationStarted) {
                return;
            }

            final int maxInactiveInterval = getMaxInactiveInterval();
            if (maxInactiveInterval > 0) {
                long newExpireTime = System.currentTimeMillis() + (maxInactiveInterval * 1000L);
                if(timerCancelKey != null && (newExpireTime < expireTime)) {
                    // We have to re-schedule as the new maxInactiveInterval is lower than the old one
                    if (!timerCancelKey.remove()) {
                        return;
                    }
                    timerCancelKey = null;
                }
                expireTime = newExpireTime;
                if(timerCancelKey == null) {
                    //+500ms, to make sure that the time has actually expired
                    //we don't re-schedule every time, as it is expensive
                    //instead when it expires we check if the timeout has been bumped, and if so we re-schedule
                    timerCancelKey = executor.executeAfter(cancelTask, (maxInactiveInterval * 1000L) + 500L, TimeUnit.MILLISECONDS);
                }
            } else {
                expireTime = -1;
                if(timerCancelKey != null) {
                    timerCancelKey.remove();
                    timerCancelKey = null;
                }
            }
            if (evictionToken != null) {
                Object token = evictionToken;
                if (evictionTokenUpdater.compareAndSet(this, token, null)) {
                    sessionManager.evictionQueue.removeToken(token);
                    this.evictionToken = sessionManager.evictionQueue.offerLastAndReturnToken(sessionId);
                }
            }
        }


        @Override
        public String getId() {
            return sessionId;
        }

        @Override
        public void requestDone(final HttpServerExchange serverExchange) {
            if (!invalid) {
                lastAccessed = System.currentTimeMillis();
            }
        }

        @Override
        public long getCreationTime() {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            return creationTime;
        }

        @Override
        public long getLastAccessedTime() {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            return lastAccessed;
        }

        @Override
        public void setMaxInactiveInterval(final int interval) {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            maxInactiveInterval = interval;
            bumpTimeout();
        }

        @Override
        public int getMaxInactiveInterval() {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            return maxInactiveInterval;
        }

        @Override
        public Object getAttribute(final String name) {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            bumpTimeout();
            return attributes.get(name);
        }

        @Override
        public Set<String> getAttributeNames() {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            bumpTimeout();
            return attributes.keySet();
        }

        @Override
        public Object setAttribute(final String name, final Object value) {
            if (value == null) {
                return removeAttribute(name);
            }
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            final Object existing = attributes.put(name, value);
            if (existing == null) {
                sessionManager.sessionListeners.attributeAdded(this, name, value);
            } else {
                sessionManager.sessionListeners.attributeUpdated(this, name, value, existing);
            }
            bumpTimeout();
            sessionManager.sessions.put(sessionId, this);
            return existing;
        }

        @Override
        public Object removeAttribute(final String name) {
            if (invalid) {
                throw UndertowMessages.MESSAGES.sessionIsInvalid(sessionId);
            }
            final Object existing = attributes.remove(name);
            sessionManager.sessionListeners.attributeRemoved(this, name, existing);
            bumpTimeout();
            sessionManager.sessions.put(sessionId, this);
            return existing;
        }

        @Override
        public void invalidate(final HttpServerExchange exchange) {
            invalidate(exchange, SessionListener.SessionDestroyedReason.INVALIDATED);
            if(exchange != null) {
                exchange.removeAttachment(sessionManager.NEW_SESSION);
            }
        }

        void invalidate(final HttpServerExchange exchange, SessionListener.SessionDestroyedReason reason) {
            synchronized(SessionImpl.this) {
                if (timerCancelKey != null) {
                    timerCancelKey.remove();
                }
                SessionImpl sess = sessionManager.sessions.remove(sessionId);
                if (sess == null) {
                    if (reason == SessionListener.SessionDestroyedReason.INVALIDATED) {
                        throw UndertowMessages.MESSAGES.sessionAlreadyInvalidated();
                    }
                    return;
                }
                invalidationStarted = true;
            }

            sessionManager.sessionListeners.sessionDestroyed(this, exchange, reason);
            invalid = true;

            if(sessionManager.statisticsEnabled) {
                long avg, newAvg;
                do {
                    avg = sessionManager.averageSessionLifetime.get();
                    BigDecimal bd = new BigDecimal(avg);
                    bd.multiply(new BigDecimal(sessionManager.expiredSessionCount.get())).add(bd);
                    newAvg = bd.divide(new BigDecimal(sessionManager.expiredSessionCount.get() + 1), MathContext.DECIMAL64).longValue();
                } while (!sessionManager.averageSessionLifetime.compareAndSet(avg, newAvg));


                sessionManager.expiredSessionCount.incrementAndGet();
                long life = System.currentTimeMillis() - creationTime;
                long existing = sessionManager.longestSessionLifetime.get();
                while (life > existing) {
                    if (sessionManager.longestSessionLifetime.compareAndSet(existing, life)) {
                        break;
                    }
                    existing = sessionManager.longestSessionLifetime.get();
                }
            }
            if (exchange != null) {
                sessionCookieConfig.clearSession(exchange, this.getId());
            }
        }

        @Override
        public SessionManager getSessionManager() {
            return sessionManager;
        }

        @Override
        public String changeSessionId(final HttpServerExchange exchange, final SessionConfig config) {
            final String oldId = sessionId;
            String newId = sessionManager.sessionIdGenerator.createSessionId();
            this.sessionId = newId;
            if(!invalid) {
                sessionManager.sessions.put(newId, this);
                config.setSessionId(exchange, this.getId());
            }
            sessionManager.sessions.remove(oldId);
            sessionManager.sessionListeners.sessionIdChanged(this, oldId);
            return newId;
        }

        private synchronized void destroy() {
            if (timerCancelKey != null) {
                timerCancelKey.remove();
            }
            cancelTask = null;
        }

    }
}
