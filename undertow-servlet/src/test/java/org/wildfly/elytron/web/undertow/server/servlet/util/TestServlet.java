/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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
package org.wildfly.elytron.web.undertow.server.servlet.util;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A simple secured HTTP servlet.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TestServlet extends HttpServlet {

    static final String PROCESSED_BY = "ProcessedBy";
    static final String UNDERTOW_USER = "UndertowUser";
    static final String ELYTRON_USER = "ElytronUser";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        manageLoginHeaders(req, resp);
        if (req.getParameter("logout") != null) {
            req.logout();
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    static void manageLoginHeaders(HttpServletRequest req, HttpServletResponse resp) {
        resp.addHeader(PROCESSED_BY, "ResponseHandler");
        String undertowUser = getUndertowUser(req);
        if (undertowUser != null) {
            resp.addHeader(UNDERTOW_USER, undertowUser);
        }
        String elytronUser = getElytronUser();
        if (elytronUser != null) {
            resp.addHeader(ELYTRON_USER, elytronUser);
        }
    }

    private static String getUndertowUser(final HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        return principal != null ? principal.getName() : null;
    }

    private static String getElytronUser() {
        SecurityDomain securityDomain = SecurityDomain.getCurrent();
        if (securityDomain != null) {
            SecurityIdentity securityIdentity = securityDomain.getCurrentSecurityIdentity();
            if (securityIdentity != null) {
                return securityIdentity.getPrincipal().getName();
            }
        }

        return null;
    }

}
