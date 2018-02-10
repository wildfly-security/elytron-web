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

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import org.jboss.metadata.javaee.jboss.RunAsIdentityMetaData;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.AuthorizationFailureException;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;

import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletChain;
import io.undertow.servlet.handlers.ServletRequestContext;

/**
 * Utility class to contain identity mapping methods.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class IdentityMapping {

    private static final String ANONYMOUS_PRINCIPAL = "anonymous";
    private static final String SERVLET = "servlet";
    private static final String EJB = "ejb";

    static SecurityIdentity mapIdentity(SecurityIdentity securityIdentity, SecurityDomain securityDomain, HttpServerExchange exchange, Function<String, RunAsIdentityMetaData> runAsMapper) {
        final ServletChain servlet = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY).getCurrentServlet();

        RunAsIdentityMetaData runAsMetaData = runAsMapper.apply(servlet.getManagedServlet().getServletInfo().getName());
        return performMapping(securityIdentity, securityDomain, runAsMetaData);
    }

    static SecurityIdentity performMapping(SecurityIdentity securityIdentity, SecurityDomain securityDomain, RunAsIdentityMetaData runAsMetaData) {
        if (runAsMetaData != null) {
            SecurityIdentity newIdentity = securityIdentity != null ? securityIdentity : securityDomain.getAnonymousSecurityIdentity();
            String runAsPrincipal = runAsMetaData.getPrincipalName();
            if (runAsPrincipal.equals(ANONYMOUS_PRINCIPAL)) {
                try {
                    newIdentity = newIdentity.createRunAsAnonymous();
                } catch (AuthorizationFailureException ex) {
                    newIdentity = newIdentity.createRunAsAnonymous(false);
                }
            } else {
                if (! runAsPrincipalExists(securityDomain, runAsPrincipal)) {
                    newIdentity = securityDomain.createAdHocIdentity(runAsPrincipal);
                } else {
                    try {
                        newIdentity = newIdentity.createRunAsIdentity(runAsPrincipal);
                    } catch (AuthorizationFailureException ex) {
                        newIdentity = newIdentity.createRunAsIdentity(runAsPrincipal, false);
                    }
                }
            }

            final Set<String> runAsRoleNames = new HashSet<>(runAsMetaData.getRunAsRoles().size());
            runAsRoleNames.add(runAsMetaData.getRoleName());
            runAsRoleNames.addAll(runAsMetaData.getRunAsRoles());

            RoleMapper runAsRoleMaper = RoleMapper.constant(Roles.fromSet(runAsRoleNames));

            Roles servletRoles = newIdentity.getRoles(SERVLET);
            newIdentity = newIdentity.withRoleMapper(SERVLET, runAsRoleMaper.or((roles) -> servletRoles));

            Roles ejbRoles = newIdentity.getRoles(EJB);
            newIdentity = newIdentity.withRoleMapper(EJB, runAsRoleMaper.or((roles) -> ejbRoles));

            return newIdentity;
        }

        return securityIdentity;
    }

    static boolean runAsPrincipalExists(final SecurityDomain securityDomain, final String runAsPrincipal) {
        RealmIdentity realmIdentity = null;
        try {
            realmIdentity = securityDomain.getIdentity(runAsPrincipal);
            return realmIdentity.exists();
        } catch (RealmUnavailableException e) {
            // TODO Throw a replcement exception
            throw new IllegalStateException(String.format("Unable to obtain identity for name %s", runAsPrincipal), e);
            //throw UndertowLogger.ROOT_LOGGER.unableToObtainIdentity(runAsPrincipal, e);
        } finally {
            if (realmIdentity != null) {
                realmIdentity.dispose();
            }
        }
    }

}
