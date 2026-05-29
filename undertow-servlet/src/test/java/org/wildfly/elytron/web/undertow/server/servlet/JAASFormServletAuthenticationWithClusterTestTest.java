/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.elytron.web.undertow.server.servlet;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.infinispan.Cache;
import org.infinispan.commons.configuration.ClassAllowList;
import org.infinispan.commons.marshall.JavaSerializationMarshaller;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.jgroups.util.UUID;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.JaasSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnManager;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionFactory;
import org.wildfly.security.http.util.sso.DefaultSingleSignOnSessionIdentifierFactory;
import org.wildfly.security.http.util.sso.SingleSignOnEntry;
import org.wildfly.security.http.util.sso.SingleSignOnManager;
import org.wildfly.security.http.util.sso.SingleSignOnServerMechanismFactory;
import org.wildfly.security.http.util.sso.SingleSignOnSessionFactory;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Hos</a>
 *
 */
public class JAASFormServletAuthenticationWithClusterTestTest extends FormAuthenticationSSOBase {

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("java.security.auth.login.config", JAASFormServletAuthenticationWithClusterTestTest.class.getResource("jaas-login.config").toString());
    }

    @AfterClass
    public static void afterClass() {
        System.clearProperty("java.security.auth.login.config");
    }

    @Rule
    public final UndertowServer serverA = createUndertowServer(7776);

    @Rule
    public final UndertowServer serverB = createUndertowServer(7777);

    public JAASFormServletAuthenticationWithClusterTestTest() throws Exception {
    }

    @Override
    protected URI createUriAppA(String alternativePath) throws URISyntaxException {
        return serverA.createUri(alternativePath);
    }

    @Override
    protected URI createUriAppB(String alternativePath) throws URISyntaxException {
        return serverB.createUri(alternativePath);
    }

    @Override
    protected String getContextRootAppA() {
        return serverA.getContextRoot();
    }

    @Override
    protected String getContextRootAppB() {
        return serverB.getContextRoot();
    }

    @Override
    protected HttpServerAuthenticationMechanismFactory getHttpServerAuthenticationMechanismFactory(Map<String, ?> properties) {
        HttpServerAuthenticationMechanismFactory delegate = super.getHttpServerAuthenticationMechanismFactory(properties);

        String cacheManagerName = UUID.randomUUID().toString();
        ClassAllowList allowList = new ClassAllowList();
        allowList.addRegexps(".*");

        EmbeddedCacheManager cacheManager = new DefaultCacheManager(
                GlobalConfigurationBuilder.defaultClusteredBuilder()
                        .globalJmxStatistics().cacheManagerName(cacheManagerName).defaultCacheName("Default")
                        .transport().nodeName(cacheManagerName).addProperty(JGroupsTransport.CONFIGURATION_FILE, "fast.xml")
                        .serialization().marshaller(new JavaSerializationMarshaller(allowList))
                        .build(),
                new ConfigurationBuilder()
                        .clustering()
                        .cacheMode(CacheMode.REPL_SYNC)
                        .build()
        );

        Cache<String, SingleSignOnEntry> cache = cacheManager.getCache();
        SingleSignOnManager manager = new DefaultSingleSignOnManager(cache, new DefaultSingleSignOnSessionIdentifierFactory(), (id, entry) -> cache.put(id, entry));
        SingleSignOnServerMechanismFactory.SingleSignOnConfiguration signOnConfiguration =
                new SingleSignOnServerMechanismFactory.SingleSignOnConfiguration("JSESSIONSSOID", null,
                        "/", false, false);

        if (keyPairSupplier == null) {
            keyPairSupplier = new KeyPairSupplier();
        }
        SingleSignOnSessionFactory singleSignOnSessionFactory = new DefaultSingleSignOnSessionFactory(manager, keyPairSupplier.get());

        return new SingleSignOnServerMechanismFactory(delegate, singleSignOnSessionFactory, signOnConfiguration);
    }

    @Override
    protected UndertowServer createUndertowServer(int port) throws Exception {
        return createUndertowServerBuilder(port).setSecurityRoles("Admin")
                .setRoleAllowed("Admin")
                .build();
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        SecurityRealm realm = new JaasSecurityRealm("Entry1", null, null, new CustomCallbackHandler());
        //SecurityRealm realm = new JaasSecurityRealm("Entry1");
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default")
                .addRealm("default", realm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        return securityDomain;
    }

}
