// Copyright © 2024 Google, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// All rights reserved.

package com.google.apigee.fakes;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.AsyncContent;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.TransportMessage;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class FakeMessage implements Message {
  private InputStream messageContentStream;
  private Map<String, Object> variables;
  private Map<String, Object> headers;
  private Map<String, Object> qparams;
  private boolean verbose = true;

  public FakeMessage() {
    setContent("");
  }

  public void setVerbose(boolean v) {
    this.verbose = v;
  }

  public boolean isVerbose() {
    return this.verbose;
  }

  public void setContent(InputStream inStream) {
    this.messageContentStream = inStream;
  }

  public void setContent(String content) {
    this.messageContentStream = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
  }

  public InputStream getContentAsStream() {
    return messageContentStream;
  }

  public String getContent() {
    return new BufferedReader(new InputStreamReader(getContentAsStream()))
        .lines()
        .collect(Collectors.joining("\n"));
  }

  private Map<String, Object> getVariables() {
    if (variables == null) {
      variables = new HashMap<String, Object>();
    }
    return variables;
  }

  private Map<String, Object> getHeaders() {
    if (headers == null) {
      headers = new HashMap<String, Object>();
    }
    return headers;
  }

  private Map<String, Object> getQparams() {
    if (qparams == null) {
      qparams = new HashMap<String, Object>();
    }
    return qparams;
  }

  public <T> T getVariable(final String name) {
    return (T) getVariables().get(name);
  }

  public boolean setVariable(final String name, final Object value) {
    getVariables().put(name, value);
    return true;
  }

  public boolean removeVariable(final String name) {
    if (getVariables().containsKey(name)) {
      variables.remove(name);
    }
    return true;
  }

  public String getHeader(final String name) {
    List<String> headerList = getHeaders(name);
    return (headerList != null) ? headerList.get(0) : null;
  }

  public List<String> getHeaders(final String name) {
    String lowerName = name.toLowerCase();
    if (getHeaders().containsKey(lowerName)) {
      @SuppressWarnings("unchecked")
      List<String> list = (List<String>) getHeaders().get(lowerName);
      return list;
    }
    return null;
  }

  public boolean setHeader(final String name, final Object value) {
    String lowerName = name.toLowerCase();
    if (isVerbose()) {
      System.out.printf("setHeader(%s) <= %s\n", lowerName, (value != null) ? value : "(null)");
    }
    if (getHeaders().containsKey(lowerName)) {
      if (!lowerName.equals("host")) {
        @SuppressWarnings("unchecked")
        List<String> values = (List<String>) getHeaders().get(lowerName);
        values.add(value.toString());
      }
    } else {
      List<String> values = new ArrayList<String>();
      values.add(value.toString());
      getHeaders().put(lowerName, values);
    }
    return true;
  }

  public boolean removeHeader(final String name) {
    String lowerName = name.toLowerCase();
    if (isVerbose()) {
      System.out.printf("removeHeader(%s)\n", lowerName);
    }
    if (getHeaders().containsKey(lowerName)) {
      getHeaders().remove(lowerName);
    }
    return true;
  }

  public Set<String> getHeaderNames() {
    return getHeaders().entrySet().stream().map(e -> e.getKey()).collect(Collectors.toSet());
  }

  public Set<String> getQueryParamNames() {
    return getQparams().entrySet().stream().map(e -> e.getKey()).collect(Collectors.toSet());
  }

  public String getQueryParam(final String name) {
    List<String> paramList = getQueryParams(name);
    return (paramList != null) ? paramList.get(0) : null;
  }

  public boolean setQueryParam(final String name, final Object value) {
    if (isVerbose()) {
      System.out.printf("setQueryParam(%s) <= %s\n", name, (value != null) ? value : "(null)");
    }
    if (getQparams().containsKey(name)) {
      @SuppressWarnings("unchecked")
      List<String> values = (List<String>) getQparams().get(name);
      values.add(value.toString());
    } else {
      List<String> values = new ArrayList<String>();
      values.add(value.toString());
      getQparams().put(name, values);
    }
    return true;
  }

  public List<String> getQueryParams(final String name) {
    if (getQparams().containsKey(name)) {
      @SuppressWarnings("unchecked")
      List<String> list = (List<String>) getQparams().get(name);
      return list;
    }
    return null;
  }

  /* ========================================================================= */
  /* Everything below this line is not implemented and not needed in this Fake */

  public String getHeader(String headerName, int index) {
    throw new UnsupportedOperationException();
  }

  public String getHeadersAsString(String headerName) {
    throw new UnsupportedOperationException();
  }

  public Object getHeadersAsObject(String headerName) {
    throw new UnsupportedOperationException();
  }

  public boolean setHeader(String name, int index, Object value) {
    throw new UnsupportedOperationException();
  }

  public boolean setHeaderWithMultipleValues(String name, Collection<String> values) {
    throw new UnsupportedOperationException();
  }

  public boolean removeSharedHeader(String headerName) {
    throw new UnsupportedOperationException();
  }

  public boolean removeHeader(String headerName, int index) {
    throw new UnsupportedOperationException();
  }

  public AsyncContent setAsyncContent(ExecutionContext ectx, MessageContext mctx) {
    throw new UnsupportedOperationException();
  }

  public void prepareForResponseFlow() {
    throw new UnsupportedOperationException();
  }

  public int getQueryParamsCount() {
    throw new UnsupportedOperationException();
  }

  public int getQueryParamValuesCount(String queryParamName) {
    throw new UnsupportedOperationException();
  }

  public String getQueryParam(String queryParamName, int index) {
    throw new UnsupportedOperationException();
  }

  public String getQueryParamsAsString(String queryParamName) {
    throw new UnsupportedOperationException();
  }

  public boolean setQueryParam(String name, int index, Object value) {
    throw new UnsupportedOperationException();
  }

  public void setQueryParamWithMultipleValues(String name, Collection<String> values) {
    throw new UnsupportedOperationException();
  }

  public boolean removeQueryParam(String queryParamName) {
    throw new UnsupportedOperationException();
  }

  public boolean removeQueryParam(String queryParamName, int index) {
    throw new UnsupportedOperationException();
  }

  public TransportMessage getTransportMessage() {
    throw new UnsupportedOperationException();
  }
}
