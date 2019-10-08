// Copyright 2018-2019 Google LLC
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

package com.google.apigee.edgecallouts.wssecdsig;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.TimeResolver;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Sign extends WssecCalloutBase implements Execution {

  private static final Logger logger = LoggerFactory.getLogger(Sign.class);

  public Sign(Map properties) {
    super(properties);
  }

  public static String toPrettyString(Document document, int indent) {
    try {
      // Remove whitespaces outside tags
      document.normalize();
      XPath xPath = XPathFactory.newInstance().newXPath();
      NodeList nodeList =
          (NodeList)
              xPath.evaluate("//text()[normalize-space()='']", document, XPathConstants.NODESET);

      for (int i = 0; i < nodeList.getLength(); ++i) {
        Node node = nodeList.item(i);
        node.getParentNode().removeChild(node);
      }

      // Setup pretty print options
      TransformerFactory transformerFactory = TransformerFactory.newInstance();
      transformerFactory.setAttribute("indent-number", indent);
      Transformer transformer = transformerFactory.newTransformer();
      transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");

      // Return pretty print xml string
      StringWriter stringWriter = new StringWriter();
      transformer.transform(new DOMSource(document), new StreamResult(stringWriter));
      return stringWriter.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // public static Element getFirstChildElement(Element element) {
  //   for (Node currentChild = element.getFirstChild();
  //        currentChild != null;
  //        currentChild = currentChild.getNextSibling()) {
  //     if (currentChild instanceof Element) {
  //       return (Element) currentChild;
  //     }
  //   }
  //   return null;
  // }

  private int nsCounter = 1;
  private String declareXmlnsPrefix(Element elt,  Map<String,String> knownNamespaces, String namespaceURIToAdd) {
    // search here for an existing prefix with the specified URI.
    String prefix = knownNamespaces.get(namespaceURIToAdd);
    if (prefix != null) {
      return prefix;
    }

    // find the default prefix for the specified URI.
    prefix = Namespaces.defaultPrefixes.get(namespaceURIToAdd);
    if (prefix == null) {
      prefix = "ns" + nsCounter++;
    }

    elt.setAttributeNS(Namespaces.XMLNS, "xmlns:" + prefix, namespaceURIToAdd);
    return prefix;
  }

  private static String getISOTimestamp(int offsetFromNow) {
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC)
      .truncatedTo(ChronoUnit.SECONDS);

    if (offsetFromNow != 0)
      zdt = zdt.plusSeconds(offsetFromNow);

    return zdt.format(DateTimeFormatter.ISO_INSTANT);

    // return ZonedDateTime.ofInstant(Instant.ofEpochSecond(secondsSinceEpoch), ZoneOffset.UTC)
    //     .format(DateTimeFormatter.ISO_INSTANT);
  }

  private byte[] sign_RSA(Document doc,
                          KeyPair kp,
                          int expiresInSeconds,
                          String configuredSigningMethod,
                          String configuredDigestMethod,
                          List<String> elementsToSign)
      throws InstantiationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          KeyException, MarshalException, XMLSignatureException, TransformerException {
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    String soapns = Namespaces.SOAP10;

    // The logic for WS-sec Signing with Binary Security Token:
    // - RSA-SHA256 or RSA-SHA1 for signature algorithm,
    // - XML-EXC-C14n# for Signature Canonicalization and
    // - XMLENC#SHA256 or SHA1 for the Digest Algorithm.

    // The process is:
    //
    // - generate and embed a Timestamp. Expires child element is optional.
    //
    //     <wsu:Timestamp wsu:Id="Timestamp-c1414e29–208f-4e5a-b0b7-f4e84ce870b9">
    //       <wsu:Created>2012–12–31T23:50:43Z</wsu:Created>
    //       <wsu:Expires>2012–12–31T23:55:43Z</wsu:Expires>
    //     </wsu:Timestamp>
    //
    // - embed the BinarySecurityToken as child of wsse:Security.  The text
    //   value is a base-64 encoded X509v3 public signer certificate that
    //   corresponds to the private key that was used to generate the
    //   digital signature
    //
    // - should sign some combination of {Timestamp, Body}.
    //
    // - embed signature element as child of SOAP:Header/ wsse:Security element
    //
    // - add KeyInfo, which is one of
    //     A. a KeyIdentifier (SOAP-UI typical case)
    //     B. a reference to the BinarySecurityToken element (WSS4J or Microsoft typical)
    //     C. an issuer name and serial number

    // KeyInfo/SecurityTokenReference could point to a BinarySecurityToken:
    //
    // <wsse:BinarySecurityToken
    //     wsu:Id=”SecurityToken-49cac4a4-b108–49eb-af80–7226774dd3e4"
    //     EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    //     ValueType=”http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">....data...</wsse:BinarySecurityToken>

    //
    // <KeyInfo>
    //   <wsse:SecurityTokenReference>
    //     <wsse:Reference URI="#SecurityToken-49cac4a4-b108–49eb-af80–7226774dd3e4"
    //        ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
    //   </wsse:SecurityTokenReference>
    // </KeyInfo>

    // KeyInfo/SecurityTokenReference could also be a KeyIdentifier
    //
    // <KeyInfo>
    //   <wsse:SecurityTokenReference
    //       wsu:Id="STRId-9E196BAFF73764EEEA12859248082589"
    //       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    //     <wsse:KeyIdentifier
    //       EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    //       ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">[SANITIZED]</wsse:KeyIdentifier>
    //  </wsse:SecurityTokenReference>
    // </KeyInfo>
    //

    // KeyInfo/SecurityTokenReference could also be a serial number:
    //
    // <KeyInfo>
    //   <wsse:SecurityTokenReference>
    //       <ds:X509Data>
    //           <ds:X509IssuerSerial>
    //               <ds:X509IssuerName>issuer information</ds:X509IssuerName>
    //               <ds:X509SerialNumber>issuer serial number</ds:X509SerialNumber>
    //           </ds:X509IssuerSerial>
    //       </ds:X509Data>
    //   </wsse:SecurityTokenReference>
    // </KeyInfo>
    //

    NodeList nodes = doc.getElementsByTagNameNS(soapns, "Envelope");
    if (nodes.getLength() != 1) {
      return null;
    }
    Element envelope = (Element) nodes.item(0);

    nodes = envelope.getElementsByTagNameNS(soapns, "Body");
    if (nodes.getLength() != 1) {
      return null;
    }

    Map<String,String> knownNamespaces = Namespaces.getExistingNamespaces(envelope);
    String wsuPrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.WSU);
    String soapPrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.SOAP10);
    String wssePrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.WSSEC);

    String bodyId = null;
    // 1. get or set the Id of the Body element
    Element body = (Element) nodes.item(0);
    if (body.hasAttributeNS(Namespaces.WSU, "Id")) {
      bodyId = body.getAttributeNS(Namespaces.WSU, "Id");
    } else {
      bodyId = "Body-" + java.util.UUID.randomUUID().toString();
      body.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", bodyId);
      //body.setIdAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", true);
      body.setIdAttributeNS(Namespaces.WSU, "Id", true);
    }

    // System.out.printf("A:\n%s\n", toPrettyString(doc, 2));

    // 2. create or get the soap:Header
    Element header = null;
    nodes = doc.getElementsByTagNameNS(soapns, "Header");
    if (nodes.getLength() == 0) {
      header = doc.createElementNS(soapns, soapPrefix + ":Header");
      envelope.insertBefore(header, body);
    } else {
      header = (Element) nodes.item(0);
    }

    // System.out.printf("B:\n%s\n", toPrettyString(doc, 2));

    // 3. create or get the WS-Security element within the header
    Element wssecHeader = null;
    nodes = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nodes.getLength() == 0) {
      wssecHeader = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":Security");
      wssecHeader.setAttributeNS(soapns, soapPrefix + ":mustUnderstand", "1");
      header.appendChild(wssecHeader);
      // envelope.insertBefore(wssecHeader, header.getFirstChild());
    } else {
      wssecHeader = (Element) nodes.item(0);
    }

    // System.out.printf("C:\n%s\n", toPrettyString(doc, 2));

    // 4. embed a Timestamp element under the wssecHeader element
    Element timestamp = doc.createElementNS(Namespaces.WSU, wsuPrefix + ":Timestamp");
    String timestampId = "Timestamp-" + java.util.UUID.randomUUID().toString();
    timestamp.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", timestampId);
    timestamp.setIdAttributeNS(Namespaces.WSU, "Id", true);
    wssecHeader.appendChild(timestamp);

    // 5a. embed a Created element into the Timestamp
    Element created = doc.createElementNS(Namespaces.WSU, wsuPrefix + ":Created");
    created.setTextContent(getISOTimestamp(0));
    timestamp.appendChild(created);

    // 5b. optionally embed an Expires element into the Timestamp
    if (expiresInSeconds > 0) {
      Element expires = doc.createElementNS(Namespaces.WSU, wsuPrefix + ":Expires");
      expires.setTextContent(getISOTimestamp(expiresInSeconds));
      timestamp.appendChild(expires);
    }

    // System.out.printf("D:\n%s\n", toPrettyString(doc, 2));
    // 6. embed the BinarySecurityToken
    // TODO!
    Element bst = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":BinarySecurityToken");
    String bstId = "SecurityToken-" + java.util.UUID.randomUUID().toString();
    bst.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", bstId);
    bst.setIdAttributeNS(Namespaces.WSU, "Id", true);
    bst.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
    bst.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
    bst.setTextContent("base64content-goes-here");
    wssecHeader.appendChild(bst);


    String digestMethodUri = ((configuredDigestMethod != null) && (configuredDigestMethod.toLowerCase().equals("sha256"))) ?
      DigestMethod.SHA256 : DigestMethod.SHA1;

    DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

    Transform transform =
        signatureFactory.newTransform(
            "http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null);
    // Transform transform =
    //     signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);

    List<Reference> references = new ArrayList<Reference>();

    if (elementsToSign == null || elementsToSign.contains("body")) {
    references.add(
        signatureFactory.newReference(
            "#" + bodyId, digestMethod, Collections.singletonList(transform), null, null));
    }

    if (elementsToSign == null || elementsToSign.contains("timestamp")) {
    references.add(
        signatureFactory.newReference(
                                      "#" + timestampId, digestMethod, Collections.singletonList(transform), null, null));
    }

    // 7. add <SignatureMethod Algorithm="..."?>
    String signingMethodUri = ((configuredSigningMethod != null) && (configuredSigningMethod.toLowerCase().equals("rsa-sha256"))) ?
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1" ;

    SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(signingMethodUri, null);

    CanonicalizationMethod canonicalizationMethod =
        signatureFactory.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);

    SignedInfo signedInfo =
        signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);
    KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
    KeyValue kv = kif.newKeyValue(kp.getPublic());

    // The marshalled XMLSignature (SignatureS?) will be added as the last child element
    // of the specified parent node.
    DOMSignContext signingContext = new DOMSignContext(kp.getPrivate(), wssecHeader);

    // For embedding a Keyinfo that holds a security token reference:
    // Element secTokenRef = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
    // javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
    // must add child element here to hold the reference.
    // KeyInfo keyInfo = keyInfoFac.newKeyInfo(java.util.Collections.singletonList(structure), "key-info-id");

    //    xxx parameterize this ^^


    XMLSignature signature =
        signatureFactory.newXMLSignature(signedInfo, kif.newKeyInfo(Collections.singletonList(kv)));
    signature.sign(signingContext);

    // emit the resulting document
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    TransformerFactory.newInstance()
        .newTransformer()
        .transform(new DOMSource(doc), new StreamResult(baos));
    return baos.toByteArray();
  }

  private static BigInteger getPublicExponent() {
    // Currently hard-coded to always return 65537, or 0xAQAB.
    // The callout could be modified to parameterize this value.
    return BigInteger.valueOf(65537);
  }

  private static KeyPair getKeyPairFromPrivateKey(PrivateKey privateKey)
      throws PEMException, InvalidKeySpecException, NoSuchAlgorithmException {
    BigInteger publicExponent = getPublicExponent();
    PublicKey publicKey =
        KeyFactory.getInstance("RSA")
            .generatePublic(
                new RSAPublicKeySpec(
                    ((RSAPrivateKey) privateKey).getPrivateExponent(), publicExponent));
    return new KeyPair(publicKey, privateKey);
  }

  private static KeyPair readKeyPair(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = new PEMParser(new StringReader(privateKeyPemString));
    Object o = pr.readObject();

    if (o == null) {
      throw new IllegalStateException("Parsed object is null.  Bad input.");
    }
    if (!((o instanceof PEMKeyPair)
        || (o instanceof PEMEncryptedKeyPair)
        || (o instanceof PKCS8EncryptedPrivateKeyInfo)
        || (o instanceof PrivateKeyInfo))) {
      // System.out.printf("found %s\n", o.getClass().getName());
      throw new IllegalStateException("Didn't find OpenSSL key. Found: " + o.getClass().getName());
    }

    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

    if (o instanceof PrivateKeyInfo) {
      return getKeyPairFromPrivateKey(converter.getPrivateKey((PrivateKeyInfo) o));
    }
    if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
      // produced by "openssl genpkey" or the series of commands reqd to sign an ec key
      // logger.info("decodePrivateKey, encrypted PrivateKeyInfo");
      PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) o;
      JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
          new JceOpenSSLPKCS8DecryptorProviderBuilder();
      InputDecryptorProvider decryptorProvider =
          decryptorProviderBuilder.build(password.toCharArray());
      PrivateKeyInfo privateKeyInfo =
          pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
      return getKeyPairFromPrivateKey(converter.getPrivateKey(privateKeyInfo));
    }

    if (o instanceof PEMEncryptedKeyPair) {
      PEMDecryptorProvider decProv =
          new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
      return converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
    }

    return converter.getKeyPair((PEMKeyPair) o);
  }

  private KeyPair getPublicPrivateKeyPair(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = privateKeyPemString.replaceAll("([\\r|\\n] +)", "\n");
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    return readKeyPair(privateKeyPemString, privateKeyPassword);
  }

  private int getExpiresIn(MessageContext msgCtxt) throws Exception {
    String expiryString = getSimpleOptionalProperty("expiry", msgCtxt);
    if (expiryString==null) return 0;
    expiryString = expiryString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(expiryString);
    if (durationInMilliseconds < 0L) return 0;
    return ((Long)(durationInMilliseconds / 1000L)).intValue();
  }

  private String getSigningMethod(MessageContext msgCtxt) throws Exception {
    String signingMethod = getSimpleOptionalProperty("signing-method", msgCtxt);
    if (signingMethod==null) return null;
    signingMethod = signingMethod.trim();
    // warn on invalid values
    if (!signingMethod.toLowerCase().equals("rsa-sha1") &&
        !signingMethod.toLowerCase().equals("rsa-sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for signing-method");
    }
    return signingMethod;
  }

  private String getDigestMethod(MessageContext msgCtxt) throws Exception {
    String digestMethod = getSimpleOptionalProperty("digest-method", msgCtxt);
    if (digestMethod==null) return null;
    digestMethod = digestMethod.trim();
    // warn on invalid values
    if (!digestMethod.toLowerCase().equals("sha1") &&
        !digestMethod.toLowerCase().equals("sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for digest-method");
    }
    return digestMethod;
  }

  private List<String> getElementsToSign(MessageContext msgCtxt) throws Exception {
    String elementList = getSimpleOptionalProperty("elements-to-sign", msgCtxt);
    if (elementList==null) return null;
    // warn on invalid values
    List<String> toSign = Arrays.asList(elementList.split(",[ ]*"))
      .stream().map(String::toLowerCase).collect(Collectors.toList());

    if (!toSign.contains("timestamp") && !toSign.contains("body")) {
      msgCtxt.setVariable(varName("WARNING"), "use timestamp or body or both in elements-to-sign");
      return null;
    }
    if (toSign.size() > 2 || toSign.size() == 0) {
      msgCtxt.setVariable(varName("WARNING"), "use timestamp or body or both in elements-to-sign");
      return null;
    }
    return toSign;
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);
      KeyPair keypair = getPublicPrivateKeyPair(msgCtxt);
      int expiresInSeconds = getExpiresIn(msgCtxt);
      String signingMethod = getSigningMethod(msgCtxt);
      String digestMethod = getDigestMethod(msgCtxt);
      List<String> elementsToSign = getElementsToSign(msgCtxt);
      byte[] resultBytes = sign_RSA(document, keypair, expiresInSeconds, signingMethod, digestMethod, elementsToSign);
      String outputVar = getOutputVar(msgCtxt);
      msgCtxt.setVariable(outputVar, new String(resultBytes, StandardCharsets.UTF_8));
      return ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      String stacktrace = getStackTraceAsString(e);
      if (getDebug()) {
        System.out.println(stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      return ExecutionResult.ABORT;
    }
  }
}
