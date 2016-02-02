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

import io.undertow.UndertowOptions;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.OpenListener;
import io.undertow.server.protocol.http.HttpOpenListener;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;

import org.junit.runner.Result;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;
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

/**
 * Following a similar approach as is used in the Undertow testsuite, a runner that starts up an Undertow server for the first
 * test and keeps it up for re-use until the last test completes.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DefaultServer extends BlockJUnit4ClassRunner {

    /**
     * Has the server already been initialised for test runs.
     */
    private static boolean initialised = false;
    private static Xnio xnio;
    private static XnioWorker worker;
    private static OptionMap serverOptions;
    private static OpenListener openListener;
    private static ChannelListener acceptListener;
    private static AcceptingChannel<? extends StreamConnection> server;


    /**
     * The {@link HttpHandler} to use for testing.
     */
    private static HttpHandler testHandler = null;

    /**
     * @param klass
     * @throws InitializationError
     */
    public DefaultServer(Class<?> klass) throws InitializationError {
        super(klass);

    }

    /**
     * Set the {@link HttpHandler} to use for the test run.
     *
     * @param testHandler the {@link HttpHandler} to use for the test run.
     */
    public static void setTestHandler(final HttpHandler testHandler) {
        DefaultServer.testHandler = testHandler;
    }

    public static URI getServerUri() throws URISyntaxException {
        return new URI("http", null, "localhost", 7776, null, null, null);
    }

    /**
     * @see org.junit.runners.ParentRunner#run(org.junit.runner.notification.RunNotifier)
     */
    @Override
    public void run(final RunNotifier notifier) {
        try {
            initialise(notifier);
        } catch (IllegalArgumentException | IOException e) {
            throw new RuntimeException(e);
        }
        super.run(notifier);
    }

    private static void initialise(final RunNotifier notifier) throws IllegalArgumentException, IOException {
        if (initialised) {
            return;
        }
        // Stolen directly from Undertow ;-)
        xnio = Xnio.getInstance("nio", DefaultServer.class.getClassLoader());
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
        acceptListener = ChannelListeners.openListenerAdapter(openListener);

        server = worker.createStreamConnectionServer(new InetSocketAddress("localhost", 7776), acceptListener, serverOptions);

        openListener.setRootHandler((HttpServerExchange exchange) -> testHandler.handleRequest(exchange));
        server.resumeAccepts();
        notifier.addListener(new RunListener() {
            @Override
            public void testRunFinished(Result result) throws Exception {
                cleanUp();
            }
        });
        initialised = true;
    }

    private static void cleanUp() throws IOException {
        server.close();
        worker.shutdown();
        server = null;
        acceptListener = null;
        openListener = null;
        serverOptions = null;
        worker = null;
        xnio = null;

        initialised = false;
    }

}
