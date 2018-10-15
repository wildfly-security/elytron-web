/*
 * Copyright 2018 Red Hat, Inc.
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

package org.wildfly.elytron.web.undertow.server.servlet;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.AttachmentKey;

/**
 * A task that can be associated with the current {@link HttpServerExchange} to perform some post request handling clean up.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface CleanUpTask {

    AttachmentKey<CleanUpTask> ATTACHMENT_KEY = AttachmentKey.create(CleanUpTask.class);

    void cleanUp(HttpServerExchange exchange) throws Exception;

}
