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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * <p>Form mechanism factory.</p>
 *
 * @author rmartinc
 */
public class CustomFormParamMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    public static final String CUSTOM_NAME = "CUSTOM_FORM_MECHANISM";

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String name, Map<String, ?> properties,
            CallbackHandler handler) throws HttpAuthenticationException {
        if (CUSTOM_NAME.equals(name)) {
            return new CustomFormParamHttpAuthenticationMechanism(handler);
        }
        return null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return new String[] { CUSTOM_NAME };
    }

}
