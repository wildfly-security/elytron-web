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

import static org.wildfly.common.Assert.checkNotNullParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.undertow.servlet.handlers.ServletRequestContext;

/**
 * A wrapper to allow the {@link HttpServletRequest} and {@link HttpServletResponse} instances to be obtained and replaced.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RequestResponseAccessor {

    /*
     * This is Undertow integration specific at the moment but at a later point this could potentially be made into an interface
     * and pulled into WildFly Elytron.
     */

    private final ServletRequestContext servletRequestContext;

    RequestResponseAccessor(final ServletRequestContext servletRequestContext) {
        this.servletRequestContext = checkNotNullParam("servletRequestContext", servletRequestContext);
    }

    HttpServletRequest getHttpServletRequest() {
        return (HttpServletRequest) servletRequestContext.getServletRequest();
    }

    void setHttpServletRequest(final HttpServletRequest httpServletRequest) {
        servletRequestContext.setServletRequest(httpServletRequest);
    }

    HttpServletResponse getHttpServletResponse() {
        return (HttpServletResponse) servletRequestContext.getServletResponse();
    }

    void setHttpServletResponse(final HttpServletResponse httpServletResponse) {
        servletRequestContext.setServletResponse(httpServletResponse);
    }

}
