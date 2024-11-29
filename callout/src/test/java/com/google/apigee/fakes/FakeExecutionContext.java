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

import com.apigee.flow.Fault;
import com.apigee.flow.execution.Callback;
import com.apigee.flow.execution.ExecutionContext;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

public class FakeExecutionContext implements ExecutionContext {
  public FakeExecutionContext() {}

  public boolean isRequestFlow() {
    throw new UnsupportedOperationException();
  }

  public boolean isErrorFlow() {
    throw new UnsupportedOperationException();
  }

  public void submitTask(Runnable task) {
    throw new UnsupportedOperationException();
  }

  public void scheduleTask(Runnable task, long delay, TimeUnit timeUnit) {
    throw new UnsupportedOperationException();
  }

  public void submitTask(Runnable task, Callback callback, Object handback) {
    throw new UnsupportedOperationException();
  }

  public void resume() {
    throw new UnsupportedOperationException();
  }

  public void resume(Fault fault) {
    throw new UnsupportedOperationException();
  }

  public boolean safeResume(Object resumeGuard) {
    throw new UnsupportedOperationException();
  }

  public boolean safeResume(Object resumeGuard, Fault fault) {
    throw new UnsupportedOperationException();
  }

  public Collection<Fault> getFaults() {
    throw new UnsupportedOperationException();
  }

  public Fault getFault() {
    throw new UnsupportedOperationException();
  }

  public void addFault(Fault fault) {
    throw new UnsupportedOperationException();
  }

  public void resumeOnNIO(Runnable runnable) {
    throw new UnsupportedOperationException();
  }
}
