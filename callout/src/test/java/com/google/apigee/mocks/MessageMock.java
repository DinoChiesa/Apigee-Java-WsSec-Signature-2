package com.google.apigee.mocks;

import com.apigee.flow.message.Message;
import com.apigee.flow.message.TransportMessage;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Set;

public class MessageMock implements Message {
  InputStream messageContentStream;

  public Set<String> getHeaderNames() {
    return null;
  }

  public String getHeader(String headerName) {
    return null;
  }

  public String getHeader(String headerName, int index) {
    return null;
  }

  public List<String> getHeaders(String headerName) {
    return null;
  }

  public String getHeadersAsString(String headerName) {
    return null;
  }

  public Object getHeadersAsObject(String headerName) {
    return null;
  }

  public boolean setHeader(String name, int index, Object value) {
    return false;
  }

  public boolean setHeader(String name, Object value) {
    return false;
  }

  public boolean setHeaderWithMultipleValues(String name, Collection<String> values) {
    return false;
  }

  public boolean removeSharedHeader(String headerName) {
    return false;
  }

  public boolean removeHeader(String headerName) {
    return false;
  }

  public boolean removeHeader(String headerName, int index) {
    return false;
  }

  public String getContent() {
    return null;
  }

  public InputStream getContentAsStream() {
    return messageContentStream;
  }

  public void setContent(InputStream inStream) {
    messageContentStream = inStream;
  }

  public void setContent(String content) {
    messageContentStream = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
  }

  public void prepareForResponseFlow() {}

  public Object getVariable(String name) {
    return null;
  }

  public boolean setVariable(String name, Object value) {
    return false;
  }

  public boolean removeVariable(String name) {
    return false;
  }

  public Set<String> getQueryParamNames() {
    return null;
  }

  public int getQueryParamValuesCount(String queryParamName) {
    return 0;
  }

  public int getQueryParamsCount() {
    return 0;
  }

  public String getQueryParam(String queryParamName) {
    return null;
  }

  public String getQueryParam(String queryParamName, int index) {
    return null;
  }

  public List<String> getQueryParams(String queryParamName) {
    return null;
  }

  public String getQueryParamsAsString(String queryParamName) {
    return null;
  }

  public boolean setQueryParam(String name, Object value) {
    return false;
  }

  public boolean setQueryParam(String name, int index, Object value) {
    return false;
  }

  public void setQueryParamWithMultipleValues(String name, Collection<String> values) {}

  public boolean removeQueryParam(String queryParamName) {
    return false;
  }

  public boolean removeQueryParam(String queryParamName, int index) {
    return false;
  }

  public TransportMessage getTransportMessage() {
    return null;
  }
}
