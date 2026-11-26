/*
 * Copyright 2026 Red Hat, Inc.
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

import io.undertow.servlet.api.SingleConstraintMatch;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.Test;
import org.wildfly.security.auth.server.SecurityDomain;

import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ElytronAuthorizationManagerTest {

    @Test
    public void testRequestUriWithColon() {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getRequestURI()).thenReturn("https://example.com/app/users/id:123/");
        when(httpServletRequest.getContextPath()).thenReturn("/app/users/id:123/");

        SingleConstraintMatch singleConstraintMatch = mock(SingleConstraintMatch.class);
        when(singleConstraintMatch.getRequiredRoles()).thenReturn(Set.of("abc"));

        ElytronAuthorizationManager elytronAuthorizationManager = new ElytronAuthorizationManager(SecurityDomain.builder().build());
        boolean canAccessResource = elytronAuthorizationManager.canAccessResource(List.of(singleConstraintMatch), null, null,
                                                                                  httpServletRequest, null);

        assertFalse(canAccessResource);
    }

}
