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

/**
 * Constants used by the Bare HTTP Utility.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class BareHttpConstants {

    private BareHttpConstants() {}

    static final String USER_AGENT = "Bare HTTP Test Utility";

    static final String CRLF = "\r\n";

    /*
     * Response Header Names
     */
    static final String CONNECTION_HEADER_NAME = "Connection";
    static final String CONTENT_LENGTH_HEADER_NAME = "Content-Length";
    static final String SET_COOKIE_HEADER_NAME = "Set-Cookie";
    static final String TRANSFER_ENCODING_COOKIE_NAME = "Transfer-Encoding";

    /*
     * Header Values
     */
    static final String CHUNKED_VALUE = "chunked";
    static final String KEEP_ALIVE_VALUE = "keep-alive";

    /*
     * Request Header Templates
     */
    static final String ACCEPT_ENCODING_HEADER = "Accept-Encoding: gzip,deflate";
    static final String CONNECTION_HEADER = CONNECTION_HEADER_NAME + ": " + KEEP_ALIVE_VALUE;
    static final String CONTENT_LENGTH_HEADER = CONTENT_LENGTH_HEADER_NAME + ": %d";
    static final String CONTENT_TYPE_HEADER = "Content-Type: application/x-www-form-urlencoded";
    static final String COOKIE_HEADER = "Cookie: %s=%s";
    static final String GET_HEADER = "GET %s HTTP/1.1";
    static final String HOST_HEADER = "Host: %s";
    static final String POST_HEADER = "POST %s HTTP/1.1";
    static final String USER_AGENT_HEADER = "User-Agent: %s";
}
