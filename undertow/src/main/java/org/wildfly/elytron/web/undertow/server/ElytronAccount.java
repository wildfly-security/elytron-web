/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.elytron.web.undertow.server;

import static org.wildfly.common.Assert.checkNotNullParam;
import io.undertow.security.idm.Account;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A wrapper around {@link AuthenticatedRealmIdentity} to provide an implementation
 * of {@link Account} as required by Undertow.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronAccount implements Account {

    private final SecurityIdentity securityIdentity;
    private final Set<String> roles;

    ElytronAccount(final SecurityIdentity securityIdentity) {
        checkNotNullParam("securityIdentity", securityIdentity);
        this.securityIdentity = securityIdentity;
        this.roles = Collections.unmodifiableSet(
                StreamSupport.stream(securityIdentity.getRoles().spliterator(), true).collect(Collectors.toSet()));
    }

    /**
     * @see io.undertow.security.idm.Account#getPrincipal()
     */
    @Override
    public Principal getPrincipal() {
        return securityIdentity.getPrincipal();
    }

    /**
     * @see io.undertow.security.idm.Account#getRoles()
     */
    @Override
    public Set<String> getRoles() {
        return roles;
    }

    /**
     * Get the {@link SecurityIdentity} wrapped by this {@link Account}.
     *
     * @return the {@link SecurityIdentity} wrapped by this {@link Account}.
     */
    SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

}
