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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

/**
 * <p>A MultiPartServlet that displays information for common parameters and
 * multi parts. Same <em>op</em> parameter is used:</p>
 *
 * <ul>
 * <li>names: getParameterNames</li>
 * <li>map: getParameterMap</li>
 * <li>value: getParameterNames + getParameter</li>
 * <li>values: getParameterNames + getParameterValues</li>
 * <li>parts: getParts</li>
 * </ul>
 *
 * @author rmartinc
 */
public class MultiPartServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        TestServlet.manageLoginHeaders(req, resp);
        String op = req.getParameter("op");
        if (op == null) {
            op = "parts";
        }
        resp.setContentType("text/plain;charset=UTF-8");
        try (PrintWriter out = resp.getWriter()) {
            if (op.equals("parts")) {
                for (Part p : req.getParts()) {
                    out.print(p.getName());
                    out.print(":");
                    out.print(p.getSubmittedFileName());
                    out.print(":");
                    out.print(p.getContentType());
                    out.print(":");
                    out.print(p.getSize());
                    out.print(":");
                    out.println(readToString(p.getInputStream()));
                }
            } else {
                ParametersServlet.processParameters(op, out, req);
            }
        }
    }

    private String readToString(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int read;
        byte[] data = new byte[512];
        while ((read = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, read);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }
}
