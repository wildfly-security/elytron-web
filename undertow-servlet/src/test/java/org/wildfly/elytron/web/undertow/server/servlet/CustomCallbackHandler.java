/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.elytron.web.undertow.server.servlet;

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class CustomCallbackHandler implements CallbackHandler {

    private Principal principal;
    private char[] evidence;

    public CustomCallbackHandler() {}

    public void setSecurityInfo(final Principal principal, final Object evidence) {
        this.principal = principal;
        if(evidence instanceof PasswordGuessEvidence) {
            this.evidence = ((PasswordGuessEvidence) evidence).getGuess();
        }
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        if (callbacks == null) {
            throw new IllegalArgumentException("The callbacks argument cannot be null");
        }

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback && principal != null) {
                NameCallback nameCallback = (NameCallback) callback;
                nameCallback.setName(this.principal.getName());
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword((this.evidence));
            } else {
                throw new UnsupportedCallbackException(callback, "Unsupported callback");
            }
        }

    }

}