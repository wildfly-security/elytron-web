package org.wildfly.elytron.web.undertow.server.util;

import io.undertow.UndertowOptions;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.OpenListener;
import io.undertow.server.protocol.http.HttpOpenListener;
import org.junit.rules.ExternalResource;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.xnio.BufferAllocator;
import org.xnio.ByteBufferSlicePool;
import org.xnio.ChannelListener;
import org.xnio.ChannelListeners;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.StreamConnection;
import org.xnio.Xnio;
import org.xnio.XnioWorker;
import org.xnio.channels.AcceptingChannel;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UndertowServer extends ExternalResource {

    private Xnio xnio;
    private XnioWorker worker;
    private OptionMap serverOptions;
    private OpenListener openListener;
    private ChannelListener acceptListener;
    private AcceptingChannel<? extends StreamConnection> server;
    private HttpHandler rootHttpHandler = null;
    private final Supplier<SSLContext> serverSslContext;
    private final int port;

    public UndertowServer(HttpHandler root) {
        this(root, (Supplier<SSLContext>) null);
    }

    public UndertowServer(HttpHandler root, int port) {
        this(root, port, null);
    }

    public UndertowServer(HttpHandler root, Supplier<SSLContext> serverSslContext) {
        this(root, 7776, serverSslContext);
    }

    public UndertowServer(HttpHandler root, int port, Supplier<SSLContext> serverSslContext) {
        this.rootHttpHandler = root;
        this.port = port;
        this.serverSslContext = serverSslContext;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return super.apply(base, description);
    }

    @Override
    protected void before() throws Throwable {
        // Stolen directly from Undertow ;-)
        xnio = Xnio.getInstance("nio", UndertowServer.class.getClassLoader());
        worker = xnio.createWorker(OptionMap.builder()
                .set(Options.WORKER_IO_THREADS, 8)
                .set(Options.CONNECTION_HIGH_WATER, 1000000)
                .set(Options.CONNECTION_LOW_WATER, 1000000)
                .set(Options.WORKER_TASK_CORE_THREADS, 30)
                .set(Options.WORKER_TASK_MAX_THREADS, 30)
                .set(Options.TCP_NODELAY, true)
                .set(Options.CORK, true)
                .getMap());

        serverOptions = OptionMap.builder()
                .set(Options.TCP_NODELAY, true)
                .set(Options.BACKLOG, 1000)
                .set(Options.REUSE_ADDRESSES, true)
                .set(Options.BALANCING_TOKENS, 1)
                .set(Options.BALANCING_CONNECTIONS, 2)
                .getMap();

        ByteBufferSlicePool pool = new ByteBufferSlicePool(BufferAllocator.BYTE_BUFFER_ALLOCATOR, 8192, 8192 * 8192);

        openListener = new HttpOpenListener(pool, OptionMap.create(UndertowOptions.BUFFER_PIPELINED_DATA, true,
                UndertowOptions.ENABLE_CONNECTOR_STATISTICS, true));
        openListener.setRootHandler((HttpServerExchange exchange) -> rootHttpHandler.handleRequest(exchange));
        acceptListener = ChannelListeners.openListenerAdapter(openListener);

        if (serverSslContext != null) {
            UndertowXnioSsl ssl = new UndertowXnioSsl(xnio, OptionMap.EMPTY, serverSslContext.get());
            server = ssl.createSslConnectionServer(worker, new InetSocketAddress("localhost", port), acceptListener, serverOptions);
        } else {
            server = worker.createStreamConnectionServer(new InetSocketAddress("localhost", port), acceptListener, serverOptions);
        }

        server.resumeAccepts();
    }

    @Override
    protected void after() {
        if (server == null) {
            return;
        }
        try {
            server.close();
            worker.shutdown();
            server = null;
            acceptListener = null;
            openListener = null;
            serverOptions = null;
            worker = null;
            xnio = null;
        } catch (IOException e) {
            throw new RuntimeException("Failed to destroy server", e);
        }
    }

    public URI getServerUri() throws URISyntaxException {
        return new URI("http", null, "localhost", port, null, null, null);
    }

    public void forceShutdown() {
        after();
    }
}
