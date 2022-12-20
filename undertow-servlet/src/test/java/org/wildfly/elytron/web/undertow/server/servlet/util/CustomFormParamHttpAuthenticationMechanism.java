/*
 * Copyright 2022 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.elytron.web.undertow.server.servlet.util;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * <p>Custom Form mechanism. It uses two form parameters to obtain the
 * username and password (X-USERNAME and X-PASSWORD). It is used to test that
 * replay is done OK.</p>
 *
 * @author rmartinc
 */
public class CustomFormParamHttpAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    public static final String USERNAME_PARAM = "X-USERNAME";
    public static final String PASSWORD_PARAM = "X-PASSWORD";
    public static final String MESSAGE_HEADER = "X-MESSAGE";

    private static final HttpServerMechanismsResponder RESPONDER = new HttpServerMechanismsResponder() {
        @Override
        public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
            response.addResponseHeader(MESSAGE_HEADER, "Please resubmit the request with a username specified using the X-USERNAME and a password specified using the X-PASSWORD form attributes.");
            response.setStatusCode(401);
        }
    };

    private final CallbackHandler callbackHandler;

    CustomFormParamHttpAuthenticationMechanism(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        final String username = request.getFirstParameterValue(USERNAME_PARAM);
        final String password = request.getFirstParameterValue(PASSWORD_PARAM);

        if (username == null || username.length() == 0 || password == null || password.length() == 0) {
            request.noAuthenticationInProgress(RESPONDER);
            return;
        }

        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password.toCharArray());
        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

        try {
            callbackHandler.handle(new Callback[] { nameCallback, evidenceVerifyCallback });
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        if (evidenceVerifyCallback.isVerified() == false) {
            request.authenticationFailed("Username / Password Validation Failed", RESPONDER);
            return;
        }

        try {
            callbackHandler.handle(new Callback[] {new IdentityCredentialCallback(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password.toCharArray())), true)});
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});

            if (authorizeCallback.isAuthorized()) {
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
                request.authenticationComplete();
            } else {
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                request.authenticationFailed("Authorization check failed.", RESPONDER);
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
    }

    @Override
    public String getMechanismName() {
        return CustomFormParamMechanismFactory.CUSTOM_NAME;
    }
}