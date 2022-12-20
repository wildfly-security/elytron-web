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
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>A Servlet that displays information for common parameters in the request.
 * The <em>op</em> parameter can be used to test a different method:</p>
 *
 * <ul>
 * <li>names: getParameterNames</li>
 * <li>map: getParameterMap</li>
 * <li>value: getParameterNames + getParameter</li>
 * <li>values: getParameterNames + getParameterValues</li>
 * </ul>
 *
 * @author rmartinc
 */
public class ParametersServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        TestServlet.manageLoginHeaders(req, resp);
        resp.setContentType("text/plain;charset=UTF-8");
        String op = req.getParameter("op");
        if (op == null) {
            op = "values";
        }
        try (PrintWriter out = resp.getWriter()) {
            processParameters(op, out, req);
        }
    }

    static void processParameters(String op, PrintWriter out, HttpServletRequest req) {
        switch (op) {
            case "names":
                writeParameterNames(out, req);
                break;
            case "map":
                writeParameterMap(out, req);
                break;
            case "value":
                writeParameterValue(out, req);
                break;
            case "values":
                writeParameterValues(out, req);
                break;
            default:
                break;
        }
    }

    private static void writeParameterNames(PrintWriter out, HttpServletRequest req) {
        Enumeration<String> e = req.getParameterNames();
        while (e.hasMoreElements()) {
            out.println(e.nextElement());
        }
    }

    private static void writeParameterMap(PrintWriter out, HttpServletRequest req) {
        Map<String, String[]> map = req.getParameterMap();
        if (map != null) {
            for (Map.Entry<String, String[]> e : map.entrySet()) {
                out.print(e.getKey());
                out.print("=");
                for (int i = 0; i < e.getValue().length; i++) {
                    if (i == e.getValue().length - 1) {
                        out.println(e.getValue()[i]);
                    } else {
                        out.print(e.getValue()[i]);
                        out.print(",");
                    }
                }
            }
        }
    }

    private static void writeParameterValues(PrintWriter out, HttpServletRequest req) {
        Enumeration<String> e = req.getParameterNames();
        while (e.hasMoreElements()) {
            String name = e.nextElement();
            out.print(name);
            out.print("=");
            String[] values = req.getParameterValues(name);
            if (values != null) {
                for (int i = 0; i < values.length; i++) {
                    if (i == values.length - 1) {
                        out.println(values[i]);
                    } else {
                        out.print(values[i]);
                        out.print(",");
                    }
                }
            }
        }
    }

    private static void writeParameterValue(PrintWriter out, HttpServletRequest req) {
        Enumeration<String> e = req.getParameterNames();
        while (e.hasMoreElements()) {
            String name = e.nextElement();
            out.print(name);
            out.print("=");
            out.println(req.getParameter(name));
        }
    }
}
