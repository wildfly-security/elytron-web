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

import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CHUNKED_VALUE;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CONNECTION_HEADER_NAME;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.CONTENT_LENGTH_HEADER_NAME;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.KEEP_ALIVE_VALUE;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.SET_COOKIE_HEADER_NAME;
import static org.wildfly.elytron.web.barehttp.BareHttpConstants.TRANSFER_ENCODING_COOKIE_NAME;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.wildfly.elytron.web.barehttp.BareHttpClient.Target;

/**
 * Representation of an HTTP Response.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BareHttpResponse {

    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String messageBody;
    private final int contentLength;
    private final boolean chunkedEncoding;

    BareHttpResponse(final Builder builder) {
        this.statusCode = builder.statusCode;
        this.headers = builder.headers;
        this.contentLength = builder.contentLength;
        this.chunkedEncoding = builder.chunkedEncoding;
        this.messageBody = toMessageBody(builder.messageBody, contentLength, chunkedEncoding);
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public String getMessageBody() {
        return messageBody;
    }

    public int getContentLength() {
        return contentLength;
    }

    public boolean isChunkedEncoding() {
        return chunkedEncoding;
    }

    private static String toMessageBody(final ByteBuffer byteBuffer, int contentLength, boolean chunkedEncoding) {
        if (!chunkedEncoding) {
            byte[] bodyBytes = new byte[contentLength];
            byteBuffer.get(bodyBytes);

            return new String(bodyBytes, StandardCharsets.UTF_8);
        } else {
            return "";
        }
    }

    static Builder builder(final Target target, final String statusLine) {
        if (!statusLine.startsWith("HTTP/1.1")) {
            throw new IllegalStateException("Not a HTTP/1.1 Response");
        }

        int statusCode = Integer.parseInt(statusLine.substring(9, 12));

        return new Builder(target, statusCode);
    }

    static class Builder {

        private final Target target;
        final int statusCode;
        final Map<String, List<String>> headers = new HashMap<>();
        ByteBuffer messageBody;
        boolean closeConnection = true;
        int contentLength = -1;
        boolean chunkedEncoding = false;

        Builder(final Target target, final int statusCode) {
            this.target = target;
            this.statusCode = statusCode;
        }

        Builder processHeader(final String header) {
            int colonPos = header.indexOf(':');
            String headerName = header.substring(0, colonPos);
            String headerValue = header.substring(colonPos + 2);

            List<String> values;
            if (headers.containsKey(headerName)) {
                values = headers.get(headerName);
            } else {
                values = new ArrayList<>();
                headers.put(headerName, values);
            }
            values.add(headerValue);

            switch (headerName) {
                case CONNECTION_HEADER_NAME:
                    if (KEEP_ALIVE_VALUE.equals(headerValue)) {
                        closeConnection = false;
                    }
                    break;
                case CONTENT_LENGTH_HEADER_NAME:
                    contentLength = Integer.parseInt(headerValue);
                    chunkedEncoding = false;
                    break;
                case SET_COOKIE_HEADER_NAME:
                    int equalsPos = headerValue.indexOf('=');
                    String cookieName = headerValue.substring(0, equalsPos);
                    int semiPos = headerValue.indexOf(';');
                    String cookieValue = semiPos < 0 ? headerValue.substring(equalsPos + 1) :
                            headerValue.substring(equalsPos + 1, semiPos);
                    target.setCookie(cookieName, cookieValue);
                    break;
                case TRANSFER_ENCODING_COOKIE_NAME:
                    if (CHUNKED_VALUE.equals(headerValue)) {
                        contentLength = -1;
                        chunkedEncoding = true;
                    }
                    break;
            }

            return this;
        }

        Builder setBody(final ByteBuffer messageBody) {
            this.messageBody = messageBody;

            return this;
        }

        public BareHttpResponse build() throws IOException {
            if (closeConnection) {
                target.close();
            }
            return new BareHttpResponse(this);
        }
    }
}
