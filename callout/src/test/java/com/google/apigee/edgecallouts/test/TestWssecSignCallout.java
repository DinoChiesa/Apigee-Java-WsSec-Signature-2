package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.edgecallouts.wssecdsig.Sign;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.HashMap;
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
  private static final String simpleSoap1 =
      "<soapenv:Envelope xmlns:ns1='http://ws.example.com/' xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>"
          + "  <soapenv:Body>"
          + "    <ns1:sumResponse>"
          + "      <ns1:return>9</ns1:return>"
          + "    </ns1:sumResponse>"
          + "  </soapenv:Body>"
          + "</soapenv:Envelope>";

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
    msgCtxt.setVariable("message-content", simpleSoap1);

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

    msgCtxt.setVariable("message.content", simpleSoap1);

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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
  public void signSha256() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
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
  public void signOnlyTimestamp() throws Exception {
    String method = "signOnlyTimestamp() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "timestamp");
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
    Assert.assertTrue(referenceUri.startsWith("#Timestamp"));

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");
  }

  @Test
  public void signOnlyBody() throws Exception {
    String method = "signOnlyBody() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "body");
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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    msgCtxt.setVariable("message.content", simpleSoap1);
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

    nl = ((Element)nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    Assert.assertEquals(nl.getLength(), 1, method + "SecurityTokenReference element");

    nl = ((Element)nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "KeyIdentifier");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyIdentifier element");
    String thumbprint = nl.item(0).getTextContent();
    Assert.assertEquals(thumbprint, "raOpRmaa1ObiyfgTYMMknkmlen0=");
  }

  @Test
  public void rawCert() throws Exception {
    String method = "rawCert() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "raw");
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

    Element keyInfo = (Element)(nl.item(0));
    nl = keyInfo.getChildNodes();
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");

    Element x509Data = (Element)(nl.item(0));
    Assert.assertEquals(x509Data.getNodeName(),"X509Data");
    nl = x509Data.getChildNodes();
    Assert.assertEquals(nl.getLength(), 1, method + "X509Certificate element");

    Element x509Cert = (Element)(nl.item(0));
    Assert.assertEquals(x509Cert.getNodeName(),"X509Certificate");
    String certText = x509Cert.getTextContent();
    Assert.assertTrue(certText.startsWith("MIIDpDCCAowCCQDsXkZg"));
    Assert.assertTrue(certText.endsWith("InG8/oOz5ib"));
  }

  @Test
  public void issuerSerial() throws Exception {
    String method = "issuerSerial() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element)(nl.item(0));

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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element)(nl.item(0));

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerName element");
    String nameString = nl.item(0).getTextContent();
    Assert.assertEquals(nameString, "C=US,ST=Washington,L=Kirkland,O=Google,OU=Apigee,CN=apigee.google.com,E=dino@apigee.com");

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, method + "X509SerialNumber element");
    String serialString = nl.item(0).getTextContent();
    Assert.assertEquals(serialString, "17032128222562009281");
  }


  @Test
  public void oldFormatPrivateKeyEncrypted() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
    msgCtxt.setVariable("message.content", simpleSoap1);
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
        "public key mismatch. The public key contained in the certificate does not match the private key.";
    String expectedException = "java.security.KeyException: " + expectedError;
    msgCtxt.setVariable("message.content", simpleSoap1);
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
}
