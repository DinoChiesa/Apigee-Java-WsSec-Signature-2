package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.edgecallouts.wssecdsig.Validate;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestWssecValidateCallout {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  InputStream messageContentStream;
  Message message;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void beforeMethod() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map variables;

          public void $init() {
            variables = new HashMap();
          }

          @Mock()
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            return (T) variables.get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap();
            }
            // System.out.printf("set %s <= (%s) %s\n", name, value.getClass().getName(),
            // value.toString());
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }

          @Mock()
          public Message getMessage() {
            return message;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();

    message =
        new MockUp<Message>() {
          @Mock()
          public InputStream getContentAsStream() {
            // new ByteArrayInputStream(messageContent.getBytes(StandardCharsets.UTF_8));
            return messageContentStream;
          }
        }.getMockInstance();
  }

  private static final String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0tNLWzRT7BcP2RMUr9wx\n"
          + "cQRaF8CoQ3mqXvC2FCuZu5Grb5T3+5cM1qylNMOoGJyWfIMIJ6WN+ZkwqjrwlOH0\n"
          + "Z2S7InnLkBPlbom5H8zRayvTZFvAq7GZAHkpWRCRLJS3TM2B/np/+sws3mkVJCW3\n"
          + "Td1NdvJMb1VIz1+AXfyEzzza4xLfbKWbL6qyIKtW0XDePJB7zbAjEVVxZqVxk4FC\n"
          + "h/ZpKJHLlT6m0tt8VxuZUunCfEUFwACVOVD+ddW4h6XbqMqjKk947j29S8QFg87a\n"
          + "vRTKgI7VN0C2D2lmq4y7E+wkNeMNrVGdaVj/yXgBaocqd9sff9yeKESS8HRk28FG\n"
          + "PQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private static final String publicKey2 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5+DmkBmXNfLurOyXzWs\n"
          + "QsDpSr2zNjB0tas+FC/ksEgL5DOJTdQLr/2wCoKnWMvt3bX69gNdKY74O+rBlPd2\n"
          + "2mwvX1ZzHKkbPN5KqTuwAWjU1G6prlDncEnMw20MLhgevRkP2H6ECFPLEB+tk2+W\n"
          + "vLbo51+pqgmYe0g+jky53y9XOf0EJi5GNDEolfp9TTbGMkAIrQ4/gU5DXnYuLwqB\n"
          + "ehn7C+GcdnSDYlzlTdH7TNlpDErMmQrpKsTgw5H3HBgVoqzld9bNwfwzXNYAn88S\n"
          + "1y8UFhFXEkiU2MpxrGMc+naLLVEpjnXIPbLB4zDg0pyiQ5ogpAdBAApPLzcBn8G1\n"
          + "RQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private static final String signedSoap1 =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><wsu:Created>2019-10-08T03:39:39Z</wsu:Created></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-61274408-e24e-4df6-b1ec-612538ced7e6\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>5zMKTwWym107y+YwQoTmfiy6LqM=</DigestValue></Reference><Reference URI=\"#Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>SF8XRy854rxcfjgYn4sCt5IkMfw=</DigestValue></Reference></SignedInfo><SignatureValue>ksG/4U2hyJfgxIhekbLE8tXJ1/QCg7MhZuYoNnNIKj1jibBfDHkAo/p1XhYjMvZHdK7pR1XWvhDu\n"
+"1XwfuUDFMFeCC4x4gY20f++tRX7BwnPiN9flIwBEn7ViUifPZ1nElMXdlDGJe9TmL8CN8TUvHkGa\n"
+"y/gEMMmIMVuEayI7X/IzGcsefovw7LEELyAwTyK1IudeflnI2NPGmBVWHnl3Z06OPSYmRSmUWP85\n"
+"OIrlI4fb8LE0iARofVawdgJj+iYut+3rsBhl4D3iwcrPZslPMBbCXqMzcJFNMxCKanDuMgog3UrL\n"
+"eEdiicloTEnBlRK0ek40tZKrr1huTbJS8sfKrA==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T\n"
+"JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo\n"
+"/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81\n"
+"vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV\n"
    +"5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-61274408-e24e-4df6-b1ec-612538ced7e6\">    <ns1:sumResponse>      <return>9</return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>\n";


  @Test
  public void test_EmptySource() throws Exception {
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "EmptySource() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_MissingPublicKey() throws Exception {
    String expectedError = "public-key resolves to an empty string";

    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "ValidResult() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "MissingKeybytes() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_RubbishPublicKey() throws Exception {
    String expectedError = "Didn't find an RSA Public Key";
    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", "this-is-not-a-valid-public-key");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "ValidResult() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "RubbishKeybytes() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_BadKey1() throws Exception {
    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", publicKey2);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "BadKey1() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "BadKey1() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "BadKey1() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void test_ValidResult() throws Exception {
    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", publicKey1);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "ValidResult() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "ValidResult() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");

    Assert.assertTrue(isValid, "ValidResult() valid");

    System.out.println("=========================================================");
  }
}
