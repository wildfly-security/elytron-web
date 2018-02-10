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

import static org.wildfly.elytron.web.undertow.server.servlet.IdentityMapping.performMapping;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.function.Function;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.ServletException;

import org.jboss.metadata.javaee.jboss.RunAsIdentityMetaData;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

import io.undertow.servlet.api.FilterInfo;
import io.undertow.servlet.api.LifecycleInterceptor;
import io.undertow.servlet.api.ServletInfo;

/**
 * A {@link LifecycleInterceptor} to associate the correct run as identity for lifecycle calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RunAsLifecycleInterceptor implements LifecycleInterceptor {

    private final Function<String, RunAsIdentityMetaData> runAsMapper;
    private final SecurityDomain securityDomain;

    RunAsLifecycleInterceptor(Function<String, RunAsIdentityMetaData> runAsMapper, SecurityDomain securityDomain) {
        this.runAsMapper = runAsMapper;
        this.securityDomain = securityDomain;
    }

    private void doIt(ServletInfo servletInfo, LifecycleContext context) throws ServletException {
        RunAsIdentityMetaData runAsMetaData = runAsMapper.apply(servletInfo.getName());

        if (runAsMetaData != null) {
            SecurityIdentity securityIdentity = performMapping(securityDomain.getAnonymousSecurityIdentity(), securityDomain, runAsMetaData);
            try {
                securityIdentity.runAs((PrivilegedExceptionAction<Void>) () -> {
                    context.proceed();
                    return null;
                });
            } catch (PrivilegedActionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof ServletException) {
                    throw (ServletException) cause;
                }
                throw new ServletException(cause);
            }
        } else {
            context.proceed();
        }
    }

    @Override
    public void init(ServletInfo servletInfo, Servlet servlet, LifecycleContext context) throws ServletException {
        doIt(servletInfo, context);
    }

    @Override
    public void init(FilterInfo filterInfo, Filter filter, LifecycleContext context) throws ServletException {
        context.proceed();
    }

    @Override
    public void destroy(ServletInfo servletInfo, Servlet servlet, LifecycleContext context) throws ServletException {
        doIt(servletInfo, context);
    }

    @Override
    public void destroy(FilterInfo filterInfo, Filter filter, LifecycleContext context) throws ServletException {
        context.proceed();
    }

}