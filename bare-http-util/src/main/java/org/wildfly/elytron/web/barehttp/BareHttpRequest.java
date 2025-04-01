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

import static org.wildfly.elytron.web.barehttp.BareHttpConstants.ACCEPT_ENCODING_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CONNECTION_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CONTENT_LENGTH_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CONTENT_TYPE_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.COOKIE_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CRLF;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.GET_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.HOST_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.POST_HEADER;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.USER_AGENT;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.USER_AGENT_HEADER;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Map.Entry;

import org.wildfly.elytron.web.barehttp.BareHttpClient.Target;

/**
 * Representation of an HTTP Request.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BareHttpRequest {

    private final Target target;
    private final String path;
    private final String messageBody;

    BareHttpRequest(final Target target, final String path, final String messageBody) {
        this.target = target;
        this.path = path;
        this.messageBody = messageBody;
    }

    public BareHttpResponse execute() throws IOException {
        target.connect();

        ByteBuffer requestMessage = createRequestByteBuffer();
        return target.sendAndReceive(requestMessage);
    }

    private ByteBuffer createRequestByteBuffer() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(baos);
        // Now add the headers.
        int contentLength = messageBody.length();
        writer.printf(contentLength > 0 ? POST_HEADER : GET_HEADER, path);
        writer.print(CRLF);
        if (contentLength > 0) {
            writer.printf(CONTENT_LENGTH_HEADER, contentLength);
            writer.print(CRLF);
            writer.print(CONTENT_TYPE_HEADER);
            writer.print(CRLF);
        }
        writer.printf(HOST_HEADER, target.getHost());
        writer.print(CRLF);
        writer.print(CONNECTION_HEADER);
        writer.print(CRLF);
        writer.printf(USER_AGENT_HEADER, USER_AGENT);
        writer.print(CRLF);
        Map<String, String> cookies = target.getCookies();
        for (Entry<String, String> current : cookies.entrySet()) {
            writer.printf(COOKIE_HEADER, current.getKey(), current.getValue());
            writer.print(CRLF);
        }
        writer.print(ACCEPT_ENCODING_HEADER);
        writer.print(CRLF);
        writer.print(CRLF);
        if (contentLength > 0) {
            writer.print(messageBody);
        }
        writer.flush();

        byte[] message = baos.toByteArray();
        ByteBuffer messageBuffer = ByteBuffer.wrap(message);

        return messageBuffer;
    }

    static Builder builder(final Target target, final String path) {
        return new Builder(target, path);
    }

    public static class Builder {

        private final Target target;
        private final String path;
        private String messageBody = "";

        Builder(final Target target, final String path) {
            this.target = target;
            this.path = path.trim().isEmpty() ? "/" : path;
        }

        public Builder setMessageBody(final String messageBody) {
            this.messageBody = messageBody;

            return this;
        }

        public BareHttpRequest build() {
            return new BareHttpRequest(target, path, messageBody);
        }

    }
}
