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

import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormData;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.spec.HttpServletRequestImpl;
import io.undertow.servlet.spec.PartImpl;
import io.undertow.servlet.spec.ServletContextImpl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.Part;

/**
 * <p>Internal class that wraps the original request and allows the replay
 * of the input stream and parsed form params.</p>
 *
 * @author rmartinc
 */
class ReplayHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private final ReplayServletInputStream ris;
    private final FormData formData;
    private List<Part> parts = null;

    public ReplayHttpServletRequestWrapper(HttpServletRequest request, FormData formData, byte[] bytes) {
        super(request);
        this.formData = formData;
        ris = new ReplayServletInputStream(bytes);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return ris;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(ris, getCharacterEncoding()));
    }

    @Override
    public String getParameter(String name) {
        String result = super.getParameter(name);
        if (result == null && formData != null) {
            FormData.FormValue fv = formData.getFirst(name);
            if (fv != null && !fv.isFileItem()) {
                result = fv.getValue();
            }
        }
        return result;
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] superValues = super.getParameterValues(name);
        List<String> result = superValues != null? new ArrayList<>(Arrays.asList(superValues)) : new ArrayList<>();
        Deque<FormData.FormValue> formValues = formData != null? formData.get(name) : null;
        if (formValues != null) {
            for (FormData.FormValue fv : formValues) {
                if (!fv.isFileItem()) {
                    result.add(fv.getValue());
                }
            }
        }
        return result.isEmpty()? null : result.toArray(new String[0]);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> result = new HashMap<>();
        Map<String, String[]> superMap = super.getParameterMap();
        if (superMap != null) {
            result.putAll(superMap);
        }
        if (formData != null) {
            for (Iterator<String> iter = formData.iterator(); iter.hasNext(); ) {
                String paramName = iter.next();
                String[] superValues = result.get(paramName);
                Deque<FormData.FormValue> fvs = formData.get(paramName);
                if (fvs != null) {
                    List<String> values = superValues != null? new ArrayList<>(Arrays.asList(superValues)) : new ArrayList<>();
                    values.addAll(getValuesFromForm(fvs));
                    if (!values.isEmpty()) {
                        result.put(paramName, values.toArray(new String[0]));
                    }
                }
            }
        }
        return Collections.unmodifiableMap(result);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        Enumeration<String> paramNames = super.getParameterNames();
        Set<String> result = new HashSet<>();
        while (paramNames.hasMoreElements()) {
            result.add(paramNames.nextElement());
        }
        if (formData != null) {
            for (Iterator<String> iter = formData.iterator(); iter.hasNext(); ) {
                String name = iter.next();
                for (FormData.FormValue fv : formData.get(name)) {
                    if (!fv.isFileItem()) {
                        result.add(name);
                        break;
                    }
                }
            }
        }
        return Collections.enumeration(result);
    }

    @Override
    public Part getPart(String name) throws IOException, ServletException {
        Part part = super.getPart(name);
        if (part != null) {
            return part;
        }
        if (parts == null) {
            loadParts();
        }
        for (Part p : parts) {
            if (p.getName().equals(name)) {
                return p;
            }
        }
        return null;
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        Collection<Part> superParts = super.getParts();
        if (superParts != null && !superParts.isEmpty()) {
            return superParts;
        }
        if (parts == null) {
            loadParts();
        }
        return parts;
    }

    private List<String> getValuesFromForm(Deque<FormData.FormValue> formValues) {
        ArrayList<String> result = new ArrayList<>();
        for (FormData.FormValue fv : formValues) {
            if (!fv.isFileItem()) {
                result.add(fv.getValue());
            }
        }
        return result;
    }

    private void loadParts() {
        HttpServletRequestImpl request = (HttpServletRequestImpl) getRequest();
        HttpServerExchange exchange = request.getExchange();
        ServletContextImpl servletContext = request.getServletContext();
        final ServletRequestContext requestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (parts == null) {
            final List<Part> tmp = new ArrayList<>();
            if(formData != null) {
                for (final String namedPart : formData) {
                    for (FormData.FormValue part : formData.get(namedPart)) {
                        tmp.add(new PartImpl(namedPart, part,
                                requestContext.getOriginalServletPathMatch().getServletChain().getManagedServlet().getMultipartConfig(),
                                servletContext, request));
                    }
                }
            }
            this.parts = tmp;
        }
    }
}
