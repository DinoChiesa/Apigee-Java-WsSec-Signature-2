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
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Validate extends WssecCalloutBase implements Execution {
  private static final int PEM_LINE_LENGTH = 64;

  public Validate(Map properties) {
    super(properties);
  }

  private static PublicKey readPublicKey(String publicKeyPemString)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    PEMParser pr = new PEMParser(new StringReader(publicKeyPemString));
    Object o = pr.readObject();
    if (o instanceof SubjectPublicKeyInfo) {
      SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) o;
      RSAPublicKey pubKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());

      PublicKey publicKey =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent()));

      return publicKey;
    }
    throw new IllegalStateException("Didn't find an RSA Public Key");
  }

  private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    String publicKeyPemString = getSimpleRequiredProperty("public-key", msgCtxt);
    publicKeyPemString = publicKeyPemString.trim();

    // clear any leading whitespace on each line
    publicKeyPemString = publicKeyPemString.replaceAll("([\\r|\\n] +)", "\n");
    return readPublicKey(publicKeyPemString);
  }

  private static Element getSecurityElement(Document doc) {
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.SOAP10, "Envelope");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: soap:Envelope");
    }
    Element envelope = (Element) nl.item(0);
    nl = envelope.getElementsByTagNameNS(Namespaces.SOAP10, "Header");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: soap:Header");
    }
    Element header = (Element) nl.item(0);
    nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: wssec:Security");
    }
    return (Element) nl.item(0);
  }

  private static NodeList getSignatures(Document doc) {
    return getSecurityElement(doc).getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
  }

  private static String toCertPEM(String s) {
    int len = s.length();
    int sIndex = 0;
    int eIndex = PEM_LINE_LENGTH;
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\n");
    while (sIndex < len) {
      sb.append(s.substring(sIndex, eIndex));
      sb.append("\n");
      sIndex += PEM_LINE_LENGTH;
      eIndex += PEM_LINE_LENGTH;
      if (eIndex > len) {
        eIndex = len;
      }
    }
    sb.append("-----END CERTIFICATE-----\n");
    s = sb.toString();
    return s;
  }

  private static Certificate getCertificateFromBase64String(String certificateString)
      throws KeyException {
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
      certificateString = toCertPEM(certificateString);
      Certificate certificate =
          certFactory.generateCertificate(
              new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
      return certificate;
    } catch (Exception ex) {
      throw new KeyException("Cannot parse X509v3 certificate.", ex);
    }
  }

  private static Element getBinarySecurityToken(String id, Document doc) {
    id = id.substring(1); // chopLeft
    NodeList nl =
        getSecurityElement(doc).getElementsByTagNameNS(Namespaces.WSSEC, "BinarySecurityToken");
    for (int i = 0; i < nl.getLength(); i++) {
      Element bst = (Element) nl.item(i);
      String bstId = bst.getAttributeNS(Namespaces.WSU, "Id");
      if (id.equals(bstId)) return bst;
    }
    return null;
  }

  private static Certificate getCertificate(Element keyInfo, Document doc) throws KeyException {
    NodeList nl = keyInfo.getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    if (nl.getLength() == 0) {
      throw new RuntimeException("No element: KeyInfo/SecurityTokenReference");
    }
    Element str = (Element) nl.item(0);
    nl = str.getElementsByTagNameNS(Namespaces.WSSEC, "Reference");
    if (nl.getLength() == 0) {
      throw new RuntimeException("No element: KeyInfo/SecurityTokenReference/Reference");
    }
    Element reference = (Element) nl.item(0);
    String strUri = reference.getAttribute("URI");
    if (strUri == null || !strUri.startsWith("#")) {
      throw new RuntimeException(
          "Unsupported URI format: KeyInfo/SecurityTokenReference/Reference");
    }
    Element bst = getBinarySecurityToken(strUri, doc);
    if (bst == null) {
      throw new RuntimeException("Unresolvable reference: #" + strUri);
    }
    String bstNs = bst.getNamespaceURI();
    String tagName = bst.getLocalName();
    if (bstNs == null
        || !bstNs.equals(Namespaces.WSSEC)
        || tagName == null
        || !tagName.equals("BinarySecurityToken")) {
      throw new RuntimeException("Unsupported SecurityTokenReference type");
    }
    String encodingType = bst.getAttribute("EncodingType");
    if (encodingType == null
        || !encodingType.equals(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")) {
      throw new RuntimeException("Unsupported SecurityTokenReference EncodingType");
    }
    String valueType = bst.getAttribute("ValueType");
    if (valueType == null
        || !valueType.equals(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")) {
      throw new RuntimeException("Unsupported SecurityTokenReference ValueType");
    }
    String base64String = bst.getTextContent();
    Certificate cert = getCertificateFromBase64String(base64String);
    return cert;
  }

  static class ValidationResult {
    private boolean _isValid;
    private List<X509Certificate> _certificates;

    public ValidationResult(boolean isValid, List<X509Certificate> certificates) {
      this._isValid = isValid;
      this._certificates = Collections.unmodifiableList(certificates);
    }

    public boolean isValid() {
      return _isValid;
    }

    public List<X509Certificate> getCertificates() {
      return _certificates;
    }
  }

  private static void markIdAttributes(Document doc) {
    NodeList nl = doc.getElementsByTagNameNS(Namespaces.SOAP10, "Body");

    if (nl.getLength() == 1) {
      Element element = (Element) nl.item(0);
      element.setIdAttributeNS(Namespaces.WSU, "Id", true);
    }
    nl = doc.getElementsByTagNameNS(Namespaces.WSU, "Timestamp");

    if (nl.getLength() == 1) {
      Element element = (Element) nl.item(0);
      element.setIdAttributeNS(Namespaces.WSU, "Id", true);
    }
  }

  private static ValidationResult validate_RSA(Document doc)
      throws MarshalException, XMLSignatureException, KeyException, CertificateExpiredException,
          CertificateNotYetValidException {
    NodeList nl = getSignatures(doc);
    if (nl.getLength() == 0) {
      throw new RuntimeException("No element: Signature");
    }

    markIdAttributes(doc);

    boolean isValid = true;
    List<X509Certificate> certs = new ArrayList<X509Certificate>();
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    for (int i = 0; i < nl.getLength(); i++) {
      if (isValid) {
        Element signatureElement = (Element) nl.item(i);
        NodeList keyinfoList =
            signatureElement.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
        if (nl.getLength() == 0) {
          throw new RuntimeException("No element: Signature/KeyInfo");
        }
        X509Certificate cert = (X509Certificate) getCertificate((Element) keyinfoList.item(0), doc);
        cert.checkValidity();
        KeySelector ks = KeySelector.singletonKeySelector(cert.getPublicKey());
        DOMValidateContext vc = new DOMValidateContext(ks, signatureElement);
        XMLSignature signature = signatureFactory.unmarshalXMLSignature(vc);
        isValid = signature.validate(vc);
        certs.add(cert);
      }
    }
    return new ValidationResult(isValid, certs);
  }

  private static boolean isExpired(Document doc, MessageContext msgCtxt) {
    NodeList nl = getSecurityElement(doc).getElementsByTagNameNS(Namespaces.WSU, "Timestamp");
    if (nl.getLength() == 0) {
      return false;
    }

    Element timestamp = (Element) nl.item(0);
    nl = timestamp.getElementsByTagNameNS(Namespaces.WSU, "Expires");
    if (nl.getLength() == 0) {
      return false;
    }
    Element expires = (Element) nl.item(0);
    TemporalAccessor creationAccessor =
        DateTimeFormatter.ISO_INSTANT.parse(expires.getTextContent());
    Instant expiry = Instant.from(creationAccessor);
    Instant now = Instant.now();
    long secondsTilExpiry = now.until(expiry, ChronoUnit.SECONDS);
    if (secondsTilExpiry <= 0L) {
      msgCtxt.setVariable(varName("error"), "the timestamp is expired");
      return true;
    }
    return false;
  }

  private boolean wantFaultOnInvalid(MessageContext msgCtxt) throws Exception {
    String wantFault = getSimpleOptionalProperty("throw-fault-on-invalid", msgCtxt);
    if (wantFault == null) return false;
    wantFault = wantFault.trim();
    if (wantFault.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  private boolean wantIgnoreTimestamp(MessageContext msgCtxt) throws Exception {
    String wantIgnore = getSimpleOptionalProperty("ignore-timestamp", msgCtxt);
    if (wantIgnore == null) return false;
    wantIgnore = wantIgnore.trim();
    if (wantIgnore.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  private List<String> getCommonNames(MessageContext msgCtxt) throws Exception {
    String nameList = getSimpleOptionalProperty("common-names", msgCtxt);
    if (nameList == null) return null;
    List<String> names =
        Arrays.asList(nameList.split(",[ ]*")).stream()
            .map(String::toLowerCase)
            .collect(Collectors.toList());
    return names;
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      msgCtxt.setVariable(varName("valid"), false);
      Document document = getDocument(msgCtxt);
      List<String> acceptableCommonNames = getCommonNames(msgCtxt);
      ValidationResult validationResult = validate_RSA(document);
      boolean isValid = validationResult.isValid();
      if (!isValid) {
        msgCtxt.setVariable(varName("error"), "signature did not verify");
      }
      if (isValid && !wantIgnoreTimestamp(msgCtxt)) {
        if (isExpired(document, msgCtxt)) {
          msgCtxt.setVariable(varName("error"), "timestamp is expired");
          isValid = false;
        }
      }
      if (isValid) {
        // check CNs of certs
        List<X509Certificate> certs = validationResult.getCertificates();
        for (int i = 0; i < certs.size(); i++) {
          X500Principal principal = certs.get(i).getSubjectX500Principal();
          LdapName ldapDN = new LdapName(principal.getName());
          for (Rdn rdn : ldapDN.getRdns()) {
            // System.out.println(rdn.getType() + " -> " + rdn.getValue());
            if (rdn.getType().equals("CN")) {
              msgCtxt.setVariable(varName("cert_" + i + "_cn"), rdn.getValue());
              if (acceptableCommonNames != null) {
                if (!acceptableCommonNames.contains(rdn.getValue())) {
                  msgCtxt.setVariable(varName("error"), "common name not accepted");
                  isValid = false;
                }
              }
            }
          }
        }
      }
      msgCtxt.setVariable(varName("valid"), isValid);
      if (isValid) {
        return ExecutionResult.SUCCESS;
      }
      return (wantFaultOnInvalid(msgCtxt)) ? ExecutionResult.ABORT : ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
  }
}
