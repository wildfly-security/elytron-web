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

import java.security.Permission;
import java.util.ArrayList;
import java.util.List;

import javax.security.jacc.WebResourcePermission;
import javax.security.jacc.WebRoleRefPermission;
import javax.servlet.http.HttpServletRequest;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

import io.undertow.security.idm.Account;
import io.undertow.servlet.api.AuthorizationManager;
import io.undertow.servlet.api.Deployment;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.SingleConstraintMatch;
import io.undertow.servlet.core.DefaultAuthorizationManager;

/**
 * Default Elytron {@link AuthorizationManager}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronAuthorizationManager implements AuthorizationManager {

    private final SecurityDomain securityDomain;

    ElytronAuthorizationManager(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    @Override
    public boolean isUserInRole(String roleName, Account account, ServletInfo servletInfo, HttpServletRequest request, Deployment deployment) {
        return DefaultAuthorizationManager.INSTANCE.isUserInRole(roleName, account, servletInfo, request, deployment);
    }

    @Override
    public boolean canAccessResource(List<SingleConstraintMatch> mappedConstraints, Account account, ServletInfo servletInfo, HttpServletRequest request, Deployment deployment) {
        if (DefaultAuthorizationManager.INSTANCE.canAccessResource(mappedConstraints, account, servletInfo, request, deployment)) {
            return true;
        }

        SecurityIdentity securityIdentity = securityDomain.getCurrentSecurityIdentity();

        if (securityIdentity == null) {
            return false;
        }

        List<Permission> permissions = new ArrayList<>();

        permissions.add(new WebResourcePermission(getCanonicalURI(request), request.getMethod()));

        for (String roleName : securityIdentity.getRoles("web", true)) {
            permissions.add(new WebRoleRefPermission(getCanonicalURI(request), roleName));
        }

        for (Permission permission : permissions) {
            if (securityIdentity.implies(permission)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public io.undertow.servlet.api.TransportGuaranteeType transportGuarantee(io.undertow.servlet.api.TransportGuaranteeType currentConnectionGuarantee, io.undertow.servlet.api.TransportGuaranteeType configuredRequiredGuarantee, HttpServletRequest request) {
        return DefaultAuthorizationManager.INSTANCE.transportGuarantee(currentConnectionGuarantee, configuredRequiredGuarantee, request);
    }

    private String getCanonicalURI(HttpServletRequest request) {
        String canonicalURI = request.getRequestURI().substring(request.getContextPath().length());
        if (canonicalURI == null || canonicalURI.equals("/"))
            canonicalURI = "";
        return canonicalURI;
    }
}
