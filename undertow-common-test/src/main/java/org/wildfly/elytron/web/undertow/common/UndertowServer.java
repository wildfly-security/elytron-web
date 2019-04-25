/*
 * Copyright 2019 Red Hat, Inc.
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

package org.wildfly.elytron.web.undertow.common;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.junit.rules.ExternalResource;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class UndertowServer extends ExternalResource {

    protected final Supplier<SSLContext> serverSslContext;
    protected final int port;
    protected final String contextRoot;
    protected final String path;

    protected UndertowServer(Supplier<SSLContext> serverSslContext, int port, String contextRoot) {
        this(serverSslContext, port, contextRoot, "");
    }

    protected UndertowServer(Supplier<SSLContext> serverSslContext, int port, String contextRoot, String path) {
        this.serverSslContext = serverSslContext;
        this.port = port;
        this.contextRoot = contextRoot != null ? contextRoot : "";
        this.path = path != null ? path : "";
    }

    public URI createUri() throws URISyntaxException {
        return this.createUri(null);
    }

    public URI createUri(String alternatePath) throws URISyntaxException {
        final String path;
        if (alternatePath != null) {
            path = this.contextRoot + alternatePath;
        } else {
            path = this.contextRoot + this.path;
        }

        System.out.println("My PATH " + path);

        return new URI((this.serverSslContext != null) ? "https" : "http", null, "localhost", this.port, path, null, null);
    }

    public void forceShutdown() {
        after();
    }

}
