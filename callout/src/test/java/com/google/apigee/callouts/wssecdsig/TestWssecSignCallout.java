// Copyright © 2018-2023 Google LLC.
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
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestWssecSignCallout extends CalloutTestBase {
  private static Document docFromStream(InputStream inputStream)
      throws IOException, ParserConfigurationException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(inputStream);
    return doc;
  }

  @Test
  public void emptySource() throws Exception {
    String method = "emptySource() ";
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", simpleSoap11);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingPrivateKey() throws Exception {
    String method = "missingPrivateKey() ";
    String expectedError = "private-key resolves to an empty string";

    msgCtxt.setVariable("message.content", simpleSoap11);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingCertificate() throws Exception {
    String method = "missingCertificate() ";
    String expectedError = "certificate resolves to an empty string";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[0].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // ws-sec header
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    Assert.assertEquals(nl.getLength(), 1, method + "WS-Security header");
    Element wssecHeader = (Element) nl.item(0);

    // signature
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // References
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void withExistingSecurityHeader() throws Exception {
    String method = "withExistingSecurityHeader() ";
    msgCtxt.setVariable("message.content", soapResponseWithEmptySecurityHeader);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // ws-sec header
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    Assert.assertEquals(nl.getLength(), 1, method + "WS-Security header");
    Element wssecHeader = (Element) nl.item(0);

    // signature
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // References
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = wssecHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void signSha256() throws Exception {
    String method = "signSha256() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("signing-method", "rsa-sha256");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (sha256)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(
        signatureMethodAlgorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void digestSha256() throws Exception {
    String method = "digestSha256() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("digest-method", "sha256");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2001/04/xmlenc#sha256");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void digestAndSigningSha256() throws Exception {
    String method = "digestAndSigningSha256() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("digest-method", "sha256");
    props.put("signing-method", "rsa-sha256");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(
        signatureMethodAlgorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2001/04/xmlenc#sha256");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void signOnlyTimestamp() throws Exception {
    String method = "signOnlyTimestamp() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "wsu:Timestamp");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    Element element = (Element) nl.item(0);
    String CanonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(CanonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");
    Element reference = (Element) nl.item(0);
    String referenceUri = reference.getAttribute("URI");
    Assert.assertTrue(referenceUri.startsWith("#TS"), "expected URI prefix");

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void signOnlyBody() throws Exception {
    String method = "signOnlyBody() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "soapenv:Body");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    Element element = (Element) nl.item(0);
    String CanonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(CanonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");
    Element reference = (Element) nl.item(0);
    String referenceUri = reference.getAttribute("URI");
    Assert.assertTrue(referenceUri.startsWith("#Body"));

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void withExpiry() throws Exception {
    String method = "withExpiry() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
    nl =
        doc.getElementsByTagNameNS(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Timestamp");
    Assert.assertEquals(nl.getLength(), 1, method + "Timestamp element");
    nl =
        doc.getElementsByTagNameNS(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Expires");
    Assert.assertEquals(nl.getLength(), 1, method + "Expires element");
    String expiryString = nl.item(0).getTextContent();
    // System.out.printf("expiry: %s\n", expiryString);
    Assert.assertNotNull(expiryString, method + "expiryString");
    TemporalAccessor creationAccessor = DateTimeFormatter.ISO_INSTANT.parse(expiryString);
    Instant expiry = Instant.from(creationAccessor);
    Instant now = Instant.now();
    long minutesTilExpiry = now.until(expiry, ChronoUnit.MINUTES);
    Assert.assertEquals(minutesTilExpiry, (long) (minutesExpiry - 1)); // rounding down
  }

  @Test
  public void thumbprint() throws Exception {
    String method = "thumbprint() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "thumbprint");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");

    nl = ((Element) nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    Assert.assertEquals(nl.getLength(), 1, method + "SecurityTokenReference element");

    nl = ((Element) nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "KeyIdentifier");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyIdentifier element");
    String thumbprint = nl.item(0).getTextContent();
    Assert.assertEquals(thumbprint, "raOpRmaa1ObiyfgTYMMknkmlen0=");
  }

  @Test
  public void rawCert() throws Exception {
    String method = "rawCert() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");

    Element keyInfo = (Element) (nl.item(0));
    nl = keyInfo.getChildNodes();
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");

    Element x509Data = (Element) (nl.item(0));
    Assert.assertEquals(x509Data.getNodeName(), "X509Data");
    nl = x509Data.getChildNodes();
    Assert.assertEquals(nl.getLength(), 1, method + "X509Certificate element");

    Element x509Cert = (Element) (nl.item(0));
    Assert.assertEquals(x509Cert.getNodeName(), "X509Certificate");
    String certText = x509Cert.getTextContent();
    Assert.assertTrue(certText.startsWith("MIIDpDCCAowCCQDsXkZg"));
    Assert.assertTrue(certText.endsWith("InG8/oOz5ib"));
  }

  @Test
  public void rsaKeyValue() throws Exception {
    String method = "rsaKeyValue() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "rsa_key_value");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "KeyValue");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyValue element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "RSAKeyValue");
    Assert.assertEquals(nl.getLength(), 1, method + "RSAKeyValue element");
    Element rsaKeyValue = (Element) (nl.item(0));

    nl = rsaKeyValue.getElementsByTagNameNS(XMLSignature.XMLNS, "Modulus");
    Assert.assertEquals(nl.getLength(), 1, method + "Modulus element");
    String modulusString = nl.item(0).getTextContent();
    Assert.assertTrue(modulusString.startsWith("AKiQNjcF3ql2lWhztJpCg6U3YTwof/NIB9"));

    nl = rsaKeyValue.getElementsByTagNameNS(XMLSignature.XMLNS, "Exponent");
    Assert.assertEquals(nl.getLength(), 1, method + "Exponent element");
    String exponentString = nl.item(0).getTextContent();
    Assert.assertEquals(exponentString, "AQAB");
  }

  @Test
  public void issuerSerial() throws Exception {
    String method = "issuerSerial() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "issuer_serial");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element) (nl.item(0));

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerName element");
    String nameString = nl.item(0).getTextContent();
    Assert.assertEquals(nameString, "CN=apigee.google.com");

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, method + "X509SerialNumber element");
    String serialString = nl.item(0).getTextContent();
    Assert.assertEquals(serialString, "17032128222562009281");
  }

  @Test
  public void issuerSerialWithLongName() throws Exception {
    String method = "issuerSerialWithLongName() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "issuer_serial");
    props.put("issuer-name-style", "subject_dn");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element) nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element) (nl.item(0));

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerName element");
    String nameString = nl.item(0).getTextContent();
    Assert.assertEquals(
        nameString,
        "C=US,ST=Washington,L=Kirkland,O=Google,OU=Apigee,CN=apigee.google.com,E=dino@apigee.com");

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, method + "X509SerialNumber element");
    String serialString = nl.item(0).getTextContent();
    Assert.assertEquals(serialString, "17032128222562009281");
  }

  @Test
  public void oldFormatPrivateKeyEncrypted() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[1].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", pairs[1].password);
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
  }

  @Test
  public void oldFormatPrivateKey() throws Exception {
    String method = "oldFormatPrivateKey() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[3].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[3].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
  }

  @Test
  public void oldFormatPrivateKeyEncryptedNoPassword() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    String expectedException =
        "org.bouncycastle.openssl.PEMException: exception processing key pair: password empty";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[1].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    // props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(
        errorOutput, "exception processing key pair: password empty", "errorOutput");
  }

  @Test
  public void mismatchedKeyAndCertificate() throws Exception {
    String method = "withCertificateMismatch() ";
    String expectedError =
        "public key mismatch. The public key contained in the certificate does not match the"
            + " private key.";
    String expectedException = "java.security.KeyException: " + expectedError;
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey); // mismatch
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, expectedError, "errorOutput");
  }

  @Test
  public void validResult_soap12() throws Exception {
    String method = "validResult_soap12() ";
    msgCtxt.setVariable("message.content", simpleSoap12);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("soap-version", "soap1.2");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Assert.assertNotNull(output);
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void soapVersionMismatch() throws Exception {
    String method = "validResult_soap12() ";
    msgCtxt.setVariable("message.content", simpleSoap12);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("soap-version", "soap1.1");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, "java.lang.IllegalStateException: No soap:Envelope found");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, "No soap:Envelope found");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void invalidSoapVersion() throws Exception {
    String method = "invalidSoapVersion() ";
    msgCtxt.setVariable("message.content", simpleSoap12);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("soap-version", "soap2.1");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    // Assert.assertNotNull(exception, method + "exception");
    Assert.assertEquals(
        exception, "java.lang.IllegalStateException: invalid value for soap-version");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, "invalid value for soap-version");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void inclusiveNamespaces() throws Exception {
    String method = "inclusiveNamespaces() ";
    msgCtxt.setVariable("message.content", altSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("elements-to-sign", "soapenv:Body");
    props.put("source", "message.content");
    props.put(
        "c14n-inclusive-namespaces",
        "http://ws.example.com/, http://schemas.xmlsoap.org/soap/envelope/,"
            + " http://www.w3.org/2001/XMLSchema, http://www.w3.org/2001/XMLSchema-instance");
    props.put(
        "transform-inclusive-namespaces",
        "http://ws.example.com/, http://www.w3.org/2001/XMLSchema,"
            + " http://www.w3.org/2001/XMLSchema-instance");
    props.put("ds-prefix", "ds");
    props.put("expiry", "10m");
    props.put("key-identifier-type", "issuer_serial");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    Element element = (Element) nl.item(0);
    String CanonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(CanonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");
    nl = element.getChildNodes();
    Assert.assertEquals(nl.getLength(), 1, method + "c14n element children");

    // InclusiveNamespaces
    Element incNamespaces = (Element) nl.item(0);
    String nsUri = incNamespaces.getNamespaceURI();
    Assert.assertEquals(nsUri, "http://www.w3.org/2001/10/xml-exc-c14n#", "InclusiveNamespaces");
    Assert.assertNotNull(incNamespaces.getAttribute("PrefixList"), "PrefixList");
    Assert.assertTrue(
        incNamespaces.getAttribute("PrefixList").indexOf("ns1") >= 0, "PrefixList ns1");
    Assert.assertTrue(
        incNamespaces.getAttribute("PrefixList").indexOf("xsi") >= 0, "PrefixList xsi");
    Assert.assertTrue(
        incNamespaces.getAttribute("PrefixList").indexOf("xsd") >= 0, "PrefixList xsd");

    // References
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void signatureConfirmations1() throws Exception {
    String method = "signatureConfirmations1() ";
    List<String> confirmationValues = Arrays.asList("abcdefg", "p12345");

    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", "2m");
    props.put("key-identifier-type", "thumbprint");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    // tell the signer to inject SignatureConfirmation elements
    props.put("confirmations", String.join(", ", confirmationValues));
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    Assert.assertEquals(nl.getLength(), 1, method + "Security element");

    nl =
        ((Element) nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC_11, "SignatureConfirmation");
    Assert.assertEquals(nl.getLength(), 2, method + "SignatureConfirmation elements");

    for (int i = 0; i < nl.getLength(); i++) {
      Element signatureConfirmation = ((Element) nl.item(i));
      Assert.assertTrue(signatureConfirmation.hasAttribute("Value"));
      Assert.assertTrue(confirmationValues.contains(signatureConfirmation.getAttribute("Value")));
    }
  }

  @Test
  public void signatureConfirmations2() throws Exception {
    String method = "signatureConfirmations2() ";

    msgCtxt.setVariable("message.content", soapResponseWithUnsignedConfirmations);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", "2m");
    props.put("key-identifier-type", "thumbprint");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("confirmations", "*all*");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    Assert.assertEquals(nl.getLength(), 1, method + "Security element");

    nl =
        ((Element) nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC_11, "SignatureConfirmation");
    Assert.assertEquals(nl.getLength(), 2, method + "SignatureConfirmation elements");

    for (int i = 0; i < nl.getLength(); i++) {
      Element signatureConfirmation = ((Element) nl.item(i));
      Assert.assertTrue(signatureConfirmation.hasAttribute("Value"));
      Assert.assertTrue(signatureConfirmation.hasAttributeNS(Namespaces.WSU, "Id"));
    }
  }

  @Test
  public void emptySignatureConfirmation() throws Exception {
    String method = "emptySignatureConfirmation() ";

    msgCtxt.setVariable("message.content", soapResponseWithEmptySecurityHeader);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", "2m");
    props.put("key-identifier-type", "thumbprint");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("confirmations", ""); // empty
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    Assert.assertEquals(nl.getLength(), 1, method + "Security element");

    // should have exactly one SignatureConfirmation element and it should have no Value attr
    nl =
        ((Element) nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC_11, "SignatureConfirmation");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureConfirmation elements");

    Element signatureConfirmation = ((Element) nl.item(0));
    Assert.assertFalse(signatureConfirmation.hasAttribute("Value"));
  }
}
