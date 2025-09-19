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
package org.wildfly.elytron.web.undertow.server.servlet;

import io.undertow.UndertowOptions;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.elytron.web.undertow.common.AbstractHttpServerMechanismTest;
import org.wildfly.elytron.web.undertow.common.UndertowServer;
import org.wildfly.elytron.web.undertow.server.servlet.util.CustomFormParamHttpAuthenticationMechanism;
import org.wildfly.elytron.web.undertow.server.servlet.util.CustomFormParamMechanismFactory;
import org.wildfly.elytron.web.undertow.server.servlet.util.UndertowServletServer;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * <p>Test that uses a custom form mechanism in order to check that
 * parameters and the input stream are available after parsing and can be
 * replayed.</p>
 *
 * @author rmartinc
 */
public class CustomFormServletAuthenticationTest extends AbstractHttpServerMechanismTest {

    @Rule
    public UndertowServer server = createUndertowServer();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    public CustomFormServletAuthenticationTest() throws Exception {
    }

    @Test
    public void testLogin() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/secured"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
        assertSuccessfulResponse(httpClient.execute(httpAuthenticate), "ladybird");
    }

    @Test
    public void testInputStream() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/input-stream"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("other", "value"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        Assert.assertEquals("X-USERNAME=ladybird&X-PASSWORD=Coleoptera&other=value",
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
    }

    @Test
    public void testParameterNames() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/parameters").toString() + "?op=names"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("other", "value1"));
        parameters.add(new BasicNameValuePair("other", "value2"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(4, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("op\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("other\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "\r\n"));
    }

    @Test
    public void testParameterValues() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/parameters").toString() + "?op=values&other=value1"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("other", "value2"));
        parameters.add(new BasicNameValuePair("other", "value3"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(4, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("op=values\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("other=value1,value2,value3\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testParameterMap() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/parameters").toString() + "?op=map&other=value1"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("other", "value2"));
        parameters.add(new BasicNameValuePair("other", "value3"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(4, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("op=map\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("other=value1,value2,value3\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testParameterValue() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/parameters").toString() + "?op=value"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("other", "value1"));
        parameters.add(new BasicNameValuePair("other", "value2"));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(4, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("op=value\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("other=value1\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testMultiPart() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/multipart"));

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        File file = folder.newFile("myfile.txt");
        Files.write(file.toPath(), "file-content".getBytes(StandardCharsets.UTF_8));
        builder.addPart("myfile.txt", new FileBody(file, ContentType.DEFAULT_TEXT));
        builder.addPart(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, new StringBody("ladybird", ContentType.MULTIPART_FORM_DATA));
        builder.addPart(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, new StringBody("Coleoptera", ContentType.MULTIPART_FORM_DATA));
        builder.addPart("param1", new StringBody("value1", ContentType.MULTIPART_FORM_DATA));
        builder.addPart("param2", new StringBody("value2", ContentType.MULTIPART_FORM_DATA));
        HttpEntity entity = builder.build();

        httpAuthenticate.setEntity(entity);

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(5, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("myfile.txt:myfile.txt:text/plain; charset=ISO-8859-1:12:file-content\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("X-USERNAME:null:null:8:ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("X-PASSWORD:null:null:10:Coleoptera\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("param1:null:null:6:value1\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("param2:null:null:6:value2\r\n"));
    }

    @Test
    public void testMultiPartValues() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/multipart").toString() + "?op=values"));

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        File file= folder.newFile("myfile.txt");
        Files.write(file.toPath(), "file-content".getBytes(StandardCharsets.UTF_8));
        builder.addPart("myfile.txt", new FileBody(file, ContentType.DEFAULT_TEXT));
        builder.addPart(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, new StringBody("ladybird", ContentType.MULTIPART_FORM_DATA));
        builder.addPart(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, new StringBody("Coleoptera", ContentType.MULTIPART_FORM_DATA));
        builder.addPart("param1", new StringBody("value1", ContentType.MULTIPART_FORM_DATA));
        builder.addPart("param2", new StringBody("value2", ContentType.MULTIPART_FORM_DATA));
        HttpEntity entity = builder.build();

        httpAuthenticate.setEntity(entity);

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(5, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("op=values\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("param1=value1\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString("param2=value2\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testFailureTooLong() throws Exception {
        StringBuilder sb = new StringBuilder(UndertowOptions.DEFAULT_MAX_BUFFERED_REQUEST_SIZE + 1);
        for (int i = 0; i <= UndertowOptions.DEFAULT_MAX_BUFFERED_REQUEST_SIZE; i++) {
            sb.append(i % 10);
        }

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(server.createUri("/parameters"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM, "ladybird"));
        parameters.add(new BasicNameValuePair(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM, "Coleoptera"));
        parameters.add(new BasicNameValuePair("long", sb.toString()));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulUnconstraintResponse(response, null);
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(3, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("long=0123456789"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testQueryParametersIfTooLong() throws Exception {
        StringBuilder sb = new StringBuilder(UndertowOptions.DEFAULT_MAX_BUFFERED_REQUEST_SIZE + 1);
        for (int i = 0; i <= UndertowOptions.DEFAULT_MAX_BUFFERED_REQUEST_SIZE; i++) {
            sb.append(i % 10);
        }

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/parameters").toString() + "?"
                + CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=" + "ladybird&"
                + CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=" + "Coleoptera"));
        List<NameValuePair> parameters = new ArrayList<>(2);

        parameters.add(new BasicNameValuePair("long", sb.toString()));

        httpAuthenticate.setEntity(new UrlEncodedFormEntity(parameters));

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        String output = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        Assert.assertEquals(3, output.codePoints().filter(ch -> ch == '\n').count());
        Assert.assertThat(output, CoreMatchers.containsString("long=0123456789"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=ladybird\r\n"));
        Assert.assertThat(output, CoreMatchers.containsString(CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=Coleoptera\r\n"));
    }

    @Test
    public void testQueryParametersIfOtherContentType() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpAuthenticate = new HttpPost(new URI(server.createUri("/input-stream").toString() + "?"
                + CustomFormParamHttpAuthenticationMechanism.USERNAME_PARAM + "=" + "ladybird&"
                + CustomFormParamHttpAuthenticationMechanism.PASSWORD_PARAM + "=" + "Coleoptera"));

        StringEntity json = new StringEntity("{\"id\":1,\"name\":\"name\"}");
        httpAuthenticate.setEntity(json);
        httpAuthenticate.setHeader("Content-type", "application/json");

        HttpResponse response = httpClient.execute(httpAuthenticate);
        assertSuccessfulResponse(response, "ladybird");
        Assert.assertEquals("{\"id\":1,\"name\":\"name\"}",
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
    }

    @Override
    protected String getMechanismName() {
        return CustomFormParamMechanismFactory.CUSTOM_NAME;
    }

    @Override
    protected SecurityDomain doCreateSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();
        passwordMap.put("ladybird", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("Coleoptera".toCharArray()))))));
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        realm.setIdentityMap(passwordMap);
        SecurityDomain.Builder builder = SecurityDomain.builder().setDefaultRealmName("TestRealm");
        builder.addRealm("TestRealm", realm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));
        return builder.build();
    }

    protected UndertowServer createUndertowServer() throws Exception {
        return UndertowServletServer.builder()
                .setAuthenticationMechanism(getMechanismName())
                .setSecurityDomain(getSecurityDomain())
                .setHttpServerAuthenticationMechanismFactory(new PropertiesServerMechanismFactory(
                                new FilterServerMechanismFactory(new CustomFormParamMechanismFactory(), true, getMechanismName()),
                                Collections.emptyMap()))
                .build();
    }
}
