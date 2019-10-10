package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.edgecallouts.wssecdsig.Validate;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestWssecValidateCallout extends CalloutTestBase {

  private static final String signedSoap1 =
      "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-2360297c-f9aa-4eee-8d77-18dc879e5c96\"><wsu:Created>2019-10-10T03:11:33Z</wsu:Created></wsu:Timestamp><wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-fc17c566-ca8f-4dc1-8831-5b7229308ea3\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-2b0a6efc-3595-4400-a86d-2ec647f47a1c\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>cXimEY2UdfeKiEBzpd5hQn5DwG8=</DigestValue></Reference><Reference URI=\"#Timestamp-2360297c-f9aa-4eee-8d77-18dc879e5c96\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>i2VsQBraiZBSj91G1Y/5gd+B9io=</DigestValue></Reference></SignedInfo><SignatureValue>EDRJmfWQ6cQ0OcHAvB1fLLMYsbyGIUxwroYkyZ4EXvY+T6n9vi5YJ78dss6WDDtOvwBpO5drzqou\n"
          + "uOogfkRDXNqu81DyIUJm9VMtitX9ORMVAeNwF6oMAj2h/hfEjt+zaT7Nknaseq6t8U47GM5ZdxOr\n"
          + "T3WVbVjm3Z8AqvrKcdRgcsEhTXvk0JI1WNEwh5GxcYxwq7WouJQmLu3WkuTlRp5RpKDMEDhnxlnv\n"
          + "Mb5N1298Zcqn5kCFYm6IMYBx/iEGRuvXBlRnroD4bVov3JTCh1CahPoOUwVQAPG5yFmv0Bz7hHbr\n"
          + "0euQAtNitxzpea3NxhB2q4B+W2ufMMAxFnS1zA==</SignatureValue><KeyInfo><wssec:SecurityTokenReference><wssec:Reference URI=\"#SecurityToken-fc17c566-ca8f-4dc1-8831-5b7229308ea3\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wssec:SecurityTokenReference></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-2b0a6efc-3595-4400-a86d-2ec647f47a1c\">    <ns1:sumResponse>      <ns1:return>9</ns1:return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>\n";

  private static final String signedSoapMissingSecurityTokenReference =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><wsu:Created>2019-10-08T03:39:39Z</wsu:Created></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-61274408-e24e-4df6-b1ec-612538ced7e6\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>5zMKTwWym107y+YwQoTmfiy6LqM=</DigestValue></Reference><Reference URI=\"#Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>SF8XRy854rxcfjgYn4sCt5IkMfw=</DigestValue></Reference></SignedInfo><SignatureValue>ksG/4U2hyJfgxIhekbLE8tXJ1/QCg7MhZuYoNnNIKj1jibBfDHkAo/p1XhYjMvZHdK7pR1XWvhDu\n"
          + "1XwfuUDFMFeCC4x4gY20f++tRX7BwnPiN9flIwBEn7ViUifPZ1nElMXdlDGJe9TmL8CN8TUvHkGa\n"
          + "y/gEMMmIMVuEayI7X/IzGcsefovw7LEELyAwTyK1IudeflnI2NPGmBVWHnl3Z06OPSYmRSmUWP85\n"
          + "OIrlI4fb8LE0iARofVawdgJj+iYut+3rsBhl4D3iwcrPZslPMBbCXqMzcJFNMxCKanDuMgog3UrL\n"
          + "eEdiicloTEnBlRK0ek40tZKrr1huTbJS8sfKrA==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T\n"
          + "JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo\n"
          + "/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81\n"
          + "vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV\n"
          + "5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-61274408-e24e-4df6-b1ec-612538ced7e6\">    <ns1:sumResponse>      <return>9</return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>\n";

  @Test
  public void emptySource() throws Exception {
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, "stacktrace");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertTrue(isValid, method + "valid");
  }

  @Test
  public void missingSecurityTokenReference() throws Exception {
    String method = "missingSecurityTokenReference() ";
    msgCtxt.setVariable("message.content", signedSoapMissingSecurityTokenReference);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "No element: KeyInfo/SecurityTokenReference");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace"); // because debug = false
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void nameMismatch() throws Exception {
    String method = "nameMismatch() ";
    msgCtxt.setVariable("message.content", signedSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("throw-fault-on-invalid", "true");
    props.put("source", "message.content");
    props.put("common-names", "abc.example.com"); // name mismatch => expect invalid

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "common name not accepted");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertFalse(isValid, method + "valid");
  }
}
