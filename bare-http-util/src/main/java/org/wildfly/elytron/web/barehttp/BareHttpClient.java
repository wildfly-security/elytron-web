/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2025 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.elytron.web.barehttp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;

/**
 * Client for sending and receiving bare HTTP messages.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BareHttpClient {

    BareHttpClient() {
    }

    public Target target(final String hostName, final int port) {
        return new Target(hostName, port);
    }

    public static Builder builder() {
        return new Builder();
    }

    public class Target {

        private final InetSocketAddress address;
        private final Map<String, String> cookies = new HashMap<>();
        private SocketChannel socketChannel;

        Target(final String hostName, final int port) {
            address = new InetSocketAddress(hostName, port);
        }

        public String getHost() {
            return address.getHostName() + ":" + address.getPort();
        }

        /**
         * Create a new connection to the target server.
         *
         * @return {@code true} if a new connection was created, {@code false} otherwise.
         * @throws IOException
         */
        boolean connect() throws IOException {
            if (isConnected()) {
                return false; // As in we are reusing the current connection.
            }

            socketChannel = SocketChannel.open(address);

            return socketChannel.isConnected();
        }

        void setCookie(final String cookieName, final String cookieValue) {
            cookies.put(cookieName, cookieValue);
        }

        Map<String, String> getCookies() {
            return cookies;
        }

        public boolean hasCookie(final String cookieName) {
            return cookies.containsKey(cookieName);
        }

        void close() throws IOException {
            if (isConnected()) {
                socketChannel.close();
                socketChannel = null;
            }
        }

        BareHttpResponse sendAndReceive(final ByteBuffer request) throws IOException {
            if (!isConnected()) {
                throw new IOException("Connection is not open.");
            }

            while(request.hasRemaining()) {
                socketChannel.write(request);
            }

            ByteBuffer responseMessage = ByteBuffer.allocate(1024);
            socketChannel.read(responseMessage);
            responseMessage.flip();

            BareHttpResponse.Builder responseBuilder = null;
            boolean complete = false;

            StringBuilder currentLine = new StringBuilder();
            while (responseMessage.hasRemaining() && !complete) {
                char c = (char) responseMessage.get();
                boolean endOfLine = false;
                if (c == '\r') {
                    if (responseMessage.hasRemaining()) {
                        responseMessage.mark();
                        char next = (char) responseMessage.get();
                        if (next == '\n') {
                            endOfLine = true;
                        } else {
                            responseMessage.reset();
                        }
                    }
                } else if (!responseMessage.hasRemaining()) {
                    endOfLine = true; // We have read all the data.
                }

                if (endOfLine) {
                    if (responseBuilder == null) {
                        responseBuilder = BareHttpResponse.builder(this, currentLine.toString());
                    } else if (currentLine.length() > 0) {
                        responseBuilder.processHeader(currentLine.toString());
                    } else {
                        responseBuilder.setBody(responseMessage);
                        complete = true;
                    }

                    currentLine = new StringBuilder();
                } else {
                    currentLine.append(c);
                }
            }

            return responseBuilder != null ? responseBuilder.build() : null;
        }

        public boolean isConnected() {
            return socketChannel != null && socketChannel.isConnected();
        }

        public BareHttpRequest.Builder buildRequest(final String path) {
            return BareHttpRequest.builder(this, path);
        }

    }


    public static class Builder {

        Builder() {
        }

        public BareHttpClient build() {
            return new BareHttpClient();
        }

    }
}
