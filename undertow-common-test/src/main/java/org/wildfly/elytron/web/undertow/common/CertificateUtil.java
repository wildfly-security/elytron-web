/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2025 Red Hat, Inc., and individual contributors
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

package org.wildfly.elytron.web.undertow.common;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;

/**
 * Utility for generating a self signed certificate on demand.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CertificateUtil {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORTHM = "SHA256withRSA";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final char[] PASSWORD = "Elytron".toCharArray();

    static X509Certificate createSelfSignedIdentity(final String alias, final X500Principal principal,
            final String workingDir, final String keyStoreName) {
        SelfSignedX509CertificateAndSigningKey selfSignedIdentity = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(principal)
                .setKeyAlgorithmName(KEY_ALGORITHM)
                .setSignatureAlgorithmName(SIGNATURE_ALGORTHM)
                .build();

        X509Certificate selfSignedCertificate = selfSignedIdentity.getSelfSignedCertificate();
        File keyStoreFile = new File(workingDir, keyStoreName);
        KeyStore keyStore = createEmptyKeyStore();
        try {
            keyStore.setKeyEntry(alias, selfSignedIdentity.getSigningKey(), PASSWORD,
                    new X509Certificate[] { selfSignedIdentity.getSelfSignedCertificate() });
            try (OutputStream out = new FileOutputStream(keyStoreFile)) {
                keyStore.store(out, PASSWORD);
            }
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return selfSignedCertificate;
    }

    private static KeyStore createEmptyKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, null);

            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
