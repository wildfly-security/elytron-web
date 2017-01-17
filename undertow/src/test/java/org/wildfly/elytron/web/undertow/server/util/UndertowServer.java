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

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.function.Supplier;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import org.junit.rules.ExternalResource;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UndertowServer extends ExternalResource {

    private Undertow server;
    private HttpHandler rootHttpHandler = null;
    private final Supplier<SSLContext> serverSslContext;
    private final int port;
    private final String deploymentName;

    public UndertowServer(HttpHandler root) {
        this(root, (Supplier<SSLContext>) null);
    }

    public UndertowServer(HttpHandler root, int port) {
        this(root, port, null, null);
    }

    public UndertowServer(HttpHandler root, int port, String deploymentName) {
        this(root, port, deploymentName, null);
    }

    public UndertowServer(HttpHandler root, Supplier<SSLContext> serverSslContext) {
        this(root, 7776, null, serverSslContext);
    }

    public UndertowServer(HttpHandler root, int port, Supplier<SSLContext> serverSslContext) {
        this(root, port, null, serverSslContext);
    }

    public UndertowServer(HttpHandler root, int port, String deploymentName, Supplier<SSLContext> serverSslContext) {
        this.rootHttpHandler = root;
        this.port = port;
        this.deploymentName = deploymentName;
        this.serverSslContext = serverSslContext;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return super.apply(base, description);
    }

    @Override
    protected void before() throws Throwable {
        Undertow.Builder builder = Undertow.builder().setBufferSize(512);

        if (serverSslContext != null) {
            builder.addHttpsListener(port,  "localhost", serverSslContext.get(), rootHttpHandler);
        } else {
            builder.addHttpListener(port, "localhost", rootHttpHandler);
        }

        server = builder.build();
        server.start();
    }

    @Override
    protected void after() {
        if (server == null) {
            return;
        }
        server.stop();
        server = null;
    }

    public URI createUri() throws URISyntaxException {
        return this.createUri("");
    }

    public URI createUri(String path) throws URISyntaxException {
        return new URI((this.serverSslContext != null) ? "https" : "http", null, "localhost", this.port, ((this.deploymentName != null) ? "/" + this.deploymentName : "") + path, null, null);
    }

    public void forceShutdown() {
        after();
    }
}
