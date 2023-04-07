/*
 * Copyright 2023 Red Hat, Inc.
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

import java.security.PrivilegedAction;

import org.wildfly.security.authz.jacc.HttpServletRequestContext;

import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Context to access the current HttpServletRequest.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UndertowHttpServletRequestContext implements HttpServletRequestContext {

    private static final PrivilegedAction<ServletRequestContext> CURRENT_CONTEXT = new PrivilegedAction<ServletRequestContext>() {
        @Override
        public ServletRequestContext run() {
            return ServletRequestContext.current();
        }
    };

    @Override
    public HttpServletRequest getCurrent() {
        ServletRequestContext context = ServletRequestContext.current();
        ServletRequest servletRequest = context != null ? context.getServletRequest() : null;
        return servletRequest instanceof HttpServletRequest ? (HttpServletRequest) servletRequest : null;
    }

}
