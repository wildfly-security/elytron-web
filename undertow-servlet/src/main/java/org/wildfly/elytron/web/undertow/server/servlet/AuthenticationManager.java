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

import java.util.function.UnaryOperator;

import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import io.undertow.servlet.api.DeploymentInfo;

/**
 * A utility class to take relevant Elytron component instances and apply them to an Undertow {@link DeploymentInfo} to apply
 * Elytron based authentication to a deployment.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthenticationManager {

    AuthenticationManager(Builder builder) {

    }

    public static Builder builder() {
        return new Builder();
    }

    static class Builder {

        private HttpAuthenticationFactory httpAuthenticationFactory;
        private boolean enableJacc;
        private boolean overrideDeploymentConfig;
        private UnaryOperator<HttpServerAuthenticationMechanismFactory> httpAuthenticationFactoryTransformer;

        private boolean built = false;

        /**
         * Set the {@link HttpAuthenticationFactory} to be used to secure the deployment.
         *
         * @param httpAuthenticationFactory the {@link HttpAuthenticationFactory} to be used to secure the deployment.
         * @return this {@link Builder}
         */
        public Builder setHttpAuthenticationFactory(final HttpAuthenticationFactory httpAuthenticationFactory) {
            assertNotBuilt();
            this.httpAuthenticationFactory = httpAuthenticationFactory;

            return this;
        }

        /**
         * Sets if JACC should be enabled for the deployment.
         *
         * @param enableJacc should jacc be enabled for this deployment.
         * @return this {@link Builder}
         */
        public Builder setEnableJacc(final boolean enableJacc) {
            assertNotBuilt();
            this.enableJacc = enableJacc;

            return this;
        }

        /**
         * Sets if the deployments authentication mechanisms should be overridden, where they are overridden all of the
         * mechanisms from the HttpAuthenticationFactory will be used with no additional filtering.
         *
         * @param overrideDeploymentConfig should the mechanisms specified in the deployment be overridden.
         * @return this {@link Builder}
         */
        public Builder setOverrideDeploymentConfig(final boolean overrideDeploymentConfig) {
            assertNotBuilt();
            this.overrideDeploymentConfig = overrideDeploymentConfig;

            return this;
        }

        /**
         * Sets a {@link UnaryOperator} to transform the {@link HttpAuthenticationFactory}.
         *
         * @param httpAuthenticationFactoryTransformer a {@link UnaryOperator} to transform the {@link HttpAuthenticationFactory}
         * @return this {@link Builder}
         */
        public Builder setHttpAuthenticationFactoryTransformer (final UnaryOperator<HttpServerAuthenticationMechanismFactory> httpAuthenticationFactoryTransformer) {
            assertNotBuilt();
            this.httpAuthenticationFactoryTransformer = httpAuthenticationFactoryTransformer;

            return this;
        }

        public AuthenticationManager build() {
            assertNotBuilt();
            built = true;
            return new AuthenticationManager(this);
        }

        void assertNotBuilt() {
            if (built) {
                throw new IllegalStateException("Builder already built.");
            }
        }
    }
}
