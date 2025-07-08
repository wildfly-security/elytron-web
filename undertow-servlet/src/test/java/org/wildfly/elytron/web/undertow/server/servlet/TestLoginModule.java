/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.elytron.web.undertow.server.servlet;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class TestLoginModule implements LoginModule {

    private final Map<String, char[]> usersMap = new HashMap<String, char[]>();
    private Principal principal;
    private Subject subject;
    private CallbackHandler handler;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        this.subject = subject;
        this.handler = callbackHandler;
        this.usersMap.put("ladybird", "Coleoptera".toCharArray());
        this.usersMap.put("dung", "Coleopterida".toCharArray());
    }

    @Override
    public boolean login() throws LoginException {

        // obtain the incoming username and password from the callback handler
        NameCallback nameCallback = new NameCallback("Username");
        PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        Callback[] callbacks = new Callback[] { nameCallback, passwordCallback };

        try {
            this.handler.handle(callbacks);
        } catch (UnsupportedCallbackException | IOException e) {
            throw new LoginException("Error handling callback: " + e.getMessage());
        }

        final String username = nameCallback.getName();
        this.setPrincipal(new NamePrincipal(username));

        final char[] password = passwordCallback.getPassword();

        char[] storedPassword = this.usersMap.get(username);
        if (!Arrays.equals(storedPassword, password)) {
            throw new LoginException("Invalid password");
        } else {
            return true;
        }
    }

    @Override
    public boolean commit() throws LoginException {
        if (this.principal.getName().equals("ladybird") || this.principal.getName().equals("dung")) {
            this.subject.getPrincipals().add(new Roles("Admin"));
            this.subject.getPrincipals().add(new Roles("User"));
            this.subject.getPrincipals().add(new Roles("Guest"));
        }
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject.getPrincipals().clear();
        return true;
    }

    public Principal getPrincipal() {
        return principal;
    }

    public void setPrincipal(Principal principal) {
        this.principal = principal;
    }

    public static class Roles implements Principal {

        private String role;

        Roles(String role) {
            this.role = role;
        }

        @Override
        public String getName() {
            return this.role;
        }
    }
}
