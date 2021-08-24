package com.google.apigee.mocks;

import com.apigee.flow.Fault;
import com.apigee.flow.execution.Callback;
import com.apigee.flow.execution.ExecutionContext;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

public final class ExecutionContextMock implements ExecutionContext {
  public boolean isRequestFlow() {
    return false;
  }

  public boolean isErrorFlow() {
    return false;
  }

  public void submitTask(Runnable task) {}

  public void scheduleTask(Runnable task, long delay, TimeUnit timeUnit) {}

  public void submitTask(Runnable task, Callback callback, Object handback) {}

  public void resume() {}

  public void resume(Fault fault) {}

  public Collection<Fault> getFaults() {
    return null;
  }

  public Fault getFault() {
    return null;
  }

  public void addFault(Fault fault) {}

  public org.slf4j.Marker getMarker() {
    return null;
  }
}
