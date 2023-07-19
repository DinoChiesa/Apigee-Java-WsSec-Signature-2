// Copyright 2017-2023 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.wssecdsig;

import com.apigee.flow.execution.ExecutionResult;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestParameterizedValidate extends CalloutTestBase {
  private static final String testDataDir = "src/test/resources/validate";

  @DataProvider(name = "batch1")
  public static Object[][] getDataForBatch1() throws IOException, IllegalStateException {
    return reallyLoad(false);
  }

  static Object[][] reallyLoad(boolean verbose) throws IOException, IllegalStateException {

    // @DataProvider requires the output to be a Object[][]. The inner
    // Object[] is the set of params that get passed to the test method.
    // So, if you want to pass just one param to the constructor, then
    // each inner Object[] must have length 1.

    ObjectMapper om = new ObjectMapper();
    om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    // Path currentRelativePath = Paths.get("");
    // String s = currentRelativePath.toAbsolutePath().toString();
    // System.out.println("Current relative path is: " + s);

    // read in all the subdirectories in the test-data directory

    File dataDir = new File(testDataDir);
    if (!dataDir.exists()) {
      throw new IllegalStateException("no test data directory.");
    }
    FilenameFilter filter = (dir, name) -> name.endsWith(".json");

    File[] jsons = dataDir.listFiles(filter);
    if (jsons.length == 0) {
      throw new IllegalStateException("no tests found.");
    }
    Arrays.sort(jsons);
    Function<File, TestCase> toTestCase =
        (jsonFile) -> {
          try {
            String name = jsonFile.getName();
            if (verbose) {
              System.out.printf("loading: %s\n", name);
            }
            if (name.indexOf("#") >= 0) {
              return null;
            }
            TestCase tc = om.readValue(jsonFile, TestCase.class);
            tc.setTestName(name.substring(0, name.length() - 5));
            return tc;
          } catch (java.lang.Exception exc1) {
            exc1.printStackTrace();
            throw new RuntimeException("uncaught exception", exc1);
          }
        };

    Function<String, Function<TestCase, TestCase>> diag =
        (stage) -> {
          return (tc) -> {
            if (verbose) {
              if (tc != null) {
                System.out.printf(
                    "stage:%s tc:%s (enabled:%s)\n", stage, tc.getTestName(), tc.getEnabled());
              } else {
                System.out.printf("stage:%s tc is null\n", stage);
              }
            }
            return tc;
          };
        };

    return Arrays.stream(jsons)
        .map(toTestCase)
        .map(diag.apply("A"))
        .filter(tc -> tc != null)
        .map(tc -> new Object[] {tc})
        .toArray(Object[][]::new);
  }

  @Test
  public void testDataProviders() throws IOException {
    Assert.assertTrue(reallyLoad(true).length > 0);
  }

  private static String resolveFileReference(String ref) throws IOException {
    return new String(Files.readAllBytes(Paths.get(testDataDir, ref.substring(7, ref.length()))));
  }

  private InputStream getInputStream(TestCase tc) throws Exception {
    if (tc.getInput() != null) {
      Path path = Paths.get(testDataDir, tc.getInput());
      if (!Files.exists(path)) {
        throw new IOException("file(" + tc.getInput() + ") not found");
      }
      return Files.newInputStream(path);
    }

    // readable empty stream
    return new ByteArrayInputStream(new byte[] {});
  }

  @Test(dataProvider = "batch1")
  public void tests(TestCase tc) throws Exception {
    if (tc.getDescription() != null)
      System.out.printf("  %10s - %s\n", tc.getTestName(), tc.getDescription());
    else System.out.printf("  %10s\n", tc.getTestName());

    if (!tc.getEnabled()) {
      System.out.printf("  SKIPPING, not enabled\n");
      return;
    }
    // set variables into message context
    for (Map.Entry<String, String> entry : tc.getContext().entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (value.startsWith("file://")) {
        value = resolveFileReference(value);
      }
      msgCtxt.setVariable(key, value);
    }

    messageContentStream = getInputStream(tc);

    Validate callout = new Validate(tc.getProperties());

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);

    String s = tc.getExpected().get("success");
    ExecutionResult expectedResult =
        (s != null && s.toLowerCase().equals("true"))
            ? ExecutionResult.SUCCESS
            : ExecutionResult.ABORT;
    // check result and output
    if (expectedResult == actualResult) {
      Set<String> expectedKeys = tc.getExpected().keySet();
      if (expectedResult != ExecutionResult.SUCCESS) {
        // must have an error if expectedResult is abort
        Assert.assertTrue(
            expectedKeys.contains("error"),
            tc.getTestName() + " misconfigured test: missing error");
      } else {
        Assert.assertTrue(
            expectedKeys.contains("valid"),
            tc.getTestName() + " misconfigured test: missing valid");
      }
      // in all cases, check all expected stuff
      for (String key : expectedKeys) {
        if (!key.equals("success")) {
          String expectedValue = tc.getExpected().get(key);
          Object outputValue = msgCtxt.getVariable("wssec_" + key);
          if (expectedValue != null) {
            Assert.assertNotNull(
                outputValue,
                String.format("%s: context variable not found wssec_%s", tc.getTestName(), key));
            String actualValueString = msgCtxt.getVariable("wssec_" + key).toString();
            Assert.assertEquals(actualValueString, expectedValue, tc.getTestName() + " " + key);
          } else {
            Assert.assertNull(outputValue, tc.getTestName() + " " + key);
          }
        }
      }
    } else {
      String observedError = msgCtxt.getVariable("wssec_error");
      System.err.printf("    observed error: %s\n", observedError);
      Assert.assertEquals(
          actualResult, expectedResult, tc.getTestName() + " result not as expected");
    }
    System.out.println("=========================================================");
  }
}
