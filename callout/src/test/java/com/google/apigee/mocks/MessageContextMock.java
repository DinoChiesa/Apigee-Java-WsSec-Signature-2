package com.google.apigee.mocks;

import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;

public final class MessageContextMock implements MessageContext {
  Message message = new MessageMock();

  private Map variables = new HashMap();

  public <T> T getVariable(final String name) {
    return (T) variables.get(name);
  }

  public boolean setVariable(final String name, final Object value) {
    System.out.printf("setVariable(%s, %s)\n", name, value == null ? "-null-" : value.toString());
    variables.put(name, value);
    return true;
  }

  public boolean removeVariable(final String name) {
    if (variables.containsKey(name)) {
      variables.remove(name);
    }
    return true;
  }

  public Message getMessage() {
    return message;
  }

  public Message createMessage(com.apigee.flow.message.TransportMessage transportMessage) {
    return null;
  }

  public boolean addFlowInfo(com.apigee.flow.FlowInfo flowInfo) {
    return false;
  }

  public void removeFlowInfo(java.lang.String string) {}

  public <T extends com.apigee.flow.FlowInfo> T getFlowInfo(String identifier) {
    return null;
  }

  public com.apigee.flow.message.Connection getClientConnection() {
    return null;
  }

  public com.apigee.flow.message.Connection getTargetConnection() {
    return null;
  }

  public com.apigee.flow.message.Message getErrorMessage() {
    return null;
  }

  public void setErrorMessage(com.apigee.flow.message.Message message) {}

  public com.apigee.flow.message.Message getResponseMessage() {
    return null;
  }

  public void setResponseMessage(com.apigee.flow.message.Message message) {}

  public com.apigee.flow.message.Message getRequestMessage() {
    return null;
  }

  public void setRequestMessage(com.apigee.flow.message.Message message) {}

  public com.apigee.flow.message.Message getMessage(
      com.apigee.flow.message.FlowContext flowContext) {
    return message;
  }

  public void setMessage(
      com.apigee.flow.message.FlowContext flowContext, com.apigee.flow.message.Message message) {}

  public String get(String name) {
    return null;
  }
}
