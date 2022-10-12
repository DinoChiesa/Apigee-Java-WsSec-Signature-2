// Copyright 2018-2022 Google LLC
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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.TimeResolver;
import com.google.apigee.util.XmlUtils;
import com.google.apigee.xml.Constants;
import com.google.apigee.xml.Namespaces;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Validate extends WssecCalloutBase implements Execution {

  private static final Logger logger = LoggerFactory.getLogger(Validate.class);

  private static final int PEM_LINE_LENGTH = 64;

  public Validate(Map properties) {
    super(properties);
  }

  private static Element getSecurityElement(Document doc, String soapNs) {
    NodeList nl = doc.getElementsByTagNameNS(soapNs, "Envelope");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: soap:Envelope");
    }
    Element envelope = (Element) nl.item(0);
    nl = envelope.getElementsByTagNameNS(soapNs, "Header");
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

  private static NodeList getSignatures(Document doc, String soapNs) {
    return getSecurityElement(doc, soapNs).getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
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

  private static Element getNamedElementWithId(
      String xmlns, String soapNs, String tagName, String id, Document doc) {
    id = id.substring(1); // chopLeft
    NodeList nl = getSecurityElement(doc, soapNs).getElementsByTagNameNS(xmlns, tagName);
    for (int i = 0; i < nl.getLength(); i++) {
      Element candidate = (Element) nl.item(i);
      String candidateId = candidate.getAttributeNS(Namespaces.WSU, "Id");
      if (id.equals(candidateId)) return candidate;
    }
    return null;
  }

  private SourcedCert getCertificate(
      Element keyInfo, Document doc, String soapNs, MessageContext msgCtxt)
      throws KeyException, NoSuchAlgorithmException, InvalidNameException,
          CertificateEncodingException {
    // There are 4 cases to handle:
    // 1. SecurityTokenReference pointing to a BinarySecurityToken
    // 2. SecurityTokenReference with KeyIdentifier via a thumbprint
    // 3. SecurityTokenReference with X509Data and X509IssuerSerial
    // 4. SecurityTokenReference with KeyIdentifier and X509v3 data
    // 5. X509Data with Raw cert data
    //
    // In cases 1, 4 and 5, we have the cert in the document. And we need to
    // check it against the trusted thumbprints.
    //
    // In cases 2 and 3, the verifier must provide the cert separately, and the
    // validity check must verify that the thumbprint or IssuerName and
    // SerialNumber asserted in the document, matches that in the certificate
    // provided explicitly to Validate.
    //
    // There is a 6th case, not handled by this callout.
    // 6. KeyValue with RSAKeyValue and Modulus + Exponent
    //
    // In case 6, the document provides a public key, not a certificate.
    // THIS callout code does not handle verification for a signed document with
    // that kind of signature.
    //

    NodeList nl = keyInfo.getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    if (nl.getLength() == 0) {
      nl = keyInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
      if (nl.getLength() == 0) throw new RuntimeException("No suitable child element of KeyInfo");
      Element x509Data = (Element) (nl.item(0));
      nl = x509Data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
      if (nl.getLength() == 0)
        throw new RuntimeException("No X509Certificate child element of KeyInfo/X509Data");

      // case 5: X509Data with raw cert data
      // <KeyInfo>
      //   <X509Data>
      //     <X509Certificate>MIICAjCCAWugAwIBAgIQwZyW5...bvc4Kzz7BQnulQ=</X509Certificate>
      //   </X509Data>
      // </KeyInfo>

      logger.debug("getCertificate() case 5: X509Data with raw data");
      Element x509Cert = (Element) (nl.item(0));
      String base64String = x509Cert.getTextContent();
      Certificate cert = certificateFromPEM(toCertPEM(base64String));
      return new SourcedCert((X509Certificate) cert, CertificateSource.DOCUMENT);
    }

    Element str = (Element) nl.item(0);
    nl = str.getElementsByTagNameNS(Namespaces.WSSEC, "Reference");
    if (nl.getLength() == 0) {
      nl = str.getElementsByTagNameNS(Namespaces.WSSEC, "KeyIdentifier");
      if (nl.getLength() == 0) {
        nl = str.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
        if (nl.getLength() == 0)
          throw new RuntimeException(
              "No suitable child element beneath: KeyInfo/SecurityTokenReference");

        logger.debug("getCertificate() case 3: IssuerName and SerialNumber");
        // case 3: SecurityTokenReference with IssuerName and SerialNumber
        // <KeyInfo>
        //   <wsse:SecurityTokenReference wsu:Id="STR-2795B41DA34FD80A771574109162615125">
        //     <X509Data>
        //       <X509IssuerSerial>
        //         <X509IssuerName>CN=creditoexpress</X509IssuerName>
        //         <X509SerialNumber>1323432320</X509SerialNumber>
        //       </X509IssuerSerial>
        //     </X509Data>
        //   </wsse:SecurityTokenReference>
        // </KeyInfo>

        Element x509Data = (Element) (nl.item(0));
        nl = x509Data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
        if (nl.getLength() == 0)
          throw new RuntimeException(
              "No X509IssuerSerial child element of KeyInfo/SecurityTokenReference/X509Data");
        Element x509IssuerSerial = (Element) (nl.item(0));
        nl = x509IssuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
        if (nl.getLength() == 0) throw new RuntimeException("No X509IssuerName element found");
        Element x509IssuerName = (Element) (nl.item(0));

        nl = x509IssuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
        if (nl.getLength() == 0) throw new RuntimeException("No X509IssuerName element found");
        Element x509SerialNumber = (Element) (nl.item(0));
        X509Certificate cert = getCertificateFromConfiguration(msgCtxt);

        // check that the serial number matches
        String assertedSerialNumber = x509SerialNumber.getTextContent();
        if (assertedSerialNumber == null)
          throw new RuntimeException("KeyInfo/SecurityTokenReference/../X509SerialNumber missing");
        String availableSerialNumber = cert.getSerialNumber().toString();
        if (!assertedSerialNumber.equals(availableSerialNumber))
          throw new RuntimeException(
              String.format(
                  "X509SerialNumber mismatch cert(%s) doc(%s)",
                  availableSerialNumber, assertedSerialNumber));

        // check that the issuer name matches
        String assertedIssuerName = x509IssuerName.getTextContent();
        if (assertedIssuerName == null)
          throw new RuntimeException("KeyInfo/SecurityTokenReference/../X509IssuerName missing");
        IssuerNameStyle nameStyle = getIssuerNameStyle(msgCtxt);

        String availableIssuerName =
            (nameStyle == IssuerNameStyle.SHORT)
                ? "CN=" + getCommonName(cert.getSubjectX500Principal())
                : cert.getSubjectDN().getName();

        if (!assertedIssuerName.equals(availableIssuerName))
          throw new RuntimeException(
              String.format(
                  "X509SerialNumber mismatch cert(%s) doc(%s)",
                  availableIssuerName, assertedIssuerName));
        return new SourcedCert(cert, CertificateSource.CONFIG);
      }
      // <KeyInfo>
      //   <wsse:SecurityTokenReference>
      //     <wsse:KeyIdentifier ...>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>

      logger.debug("getCertificate() KeyIdentifier");
      Element ki = (Element) nl.item(0);
      String valueType = ki.getAttribute("ValueType");
      if (valueType == null) {
        throw new RuntimeException(
            "KeyInfo/SecurityTokenReference/KeyIdentifier missing ValueType");
      }
      if (!valueType.equals(Constants.X509_V3_TYPE)
          && !valueType.equals(Constants.THUMBPRINT_SHA1)) {
        throw new RuntimeException(
            "KeyInfo/SecurityTokenReference/KeyIdentifier unsupported ValueType");
      }
      if (valueType.equals(Constants.X509_V3_TYPE)) {
        // case 4: x509v3 cert base64 encoded
        // <KeyInfo>
        //   <wsse:SecurityTokenReference>
        //     <wsse:KeyIdentifier
        //
        // EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        //
        // ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">CERT_HERE</wsse:KeyIdentifier>
        //   </wsse:SecurityTokenReference>
        // </KeyInfo>
        String encodingType = ki.getAttribute("EncodingType");
        if (encodingType == null)
          throw new RuntimeException("Unsupported SecurityTokenReference EncodingType (null)");
        if (!encodingType.equals(Constants.BASE64_BINARY))
          throw new RuntimeException(
              String.format("Unsupported SecurityTokenReference EncodingType (%s)", encodingType));

        logger.debug("getCertificate() case 4: KeyIdentifier with raw cert data");
        String base64String = ki.getTextContent();
        Certificate cert = certificateFromPEM(toCertPEM(base64String));
        return new SourcedCert((X509Certificate) cert, CertificateSource.DOCUMENT);
      }

      // <KeyInfo>
      //   <wsse:SecurityTokenReference>
      //     <wsse:KeyIdentifier
      //
      // ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">THUMBPRINT</wsse:KeyIdentifier>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      //
      String assertedThumbprintSha1Base64 = ki.getTextContent();
      if (assertedThumbprintSha1Base64 == null)
        throw new RuntimeException("KeyInfo/SecurityTokenReference/KeyIdentifier no thumbprint");

      logger.debug(
          "getCertificate() case 2: SecurityTokenReference with KeyIdentifier and thumbprint");
      X509Certificate cert = getCertificateFromConfiguration(msgCtxt);
      String availableThumbprintSha1Base64 = getThumbprintBase64(cert);
      if (!assertedThumbprintSha1Base64.equals(availableThumbprintSha1Base64))
        throw new RuntimeException(
            "KeyInfo/SecurityTokenReference/KeyIdentifier thumbprint mismatch");

      return new SourcedCert(cert, CertificateSource.CONFIG);
    }

    // case 1: SecurityTokenReference pointing to a BinarySecurityToken
    // <KeyInfo>
    //   <wssec:SecurityTokenReference>
    //     <wssec:Reference URI="#SecurityToken-e828bfab-bb52-4429"
    //
    // ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
    //   </wssec:SecurityTokenReference>
    // </KeyInfo>

    logger.debug(
        "getCertificate() case 1: SecurityTokenReference pointing to a BinarySecurityToken");
    Element reference = (Element) nl.item(0);
    String strUri = reference.getAttribute("URI");
    if (strUri == null || !strUri.startsWith("#")) {
      throw new RuntimeException(
          "Unsupported URI format: KeyInfo/SecurityTokenReference/Reference");
    }
    Element bst =
        getNamedElementWithId(Namespaces.WSSEC, soapNs, "BinarySecurityToken", strUri, doc);
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
    if (encodingType == null)
      throw new RuntimeException("Unsupported SecurityTokenReference EncodingType (null)");
    if (!encodingType.equals(Constants.BASE64_BINARY))
      throw new RuntimeException(
          String.format("Unsupported SecurityTokenReference EncodingType (%s)", encodingType));

    String valueType = bst.getAttribute("ValueType");
    if (valueType == null)
      throw new RuntimeException("Unsupported SecurityTokenReference ValueType");
    if (!valueType.equals(Constants.X509_V3_TYPE))
      throw new RuntimeException(
          String.format("Unsupported SecurityTokenReference ValueType (%s)", valueType));

    // check encoding type here?
    String base64String = bst.getTextContent();
    Certificate cert = certificateFromPEM(toCertPEM(base64String));
    return new SourcedCert((X509Certificate) cert, CertificateSource.DOCUMENT);
  }

  enum CertificateSource {
    NOT_SPECIFIED,
    CONFIG,
    DOCUMENT;
  }

  static class SourcedCert {
    public X509Certificate certificate;
    public CertificateSource source;

    public SourcedCert(X509Certificate certificate, CertificateSource source) {
      this.source = source;
      this.certificate = certificate;
    }
  }

  static class ValidationResult {
    private boolean _isValid;
    private Map<X509Certificate, String> _thumbprints;
    private List<X509Certificate> _certificates;

    private ValidationResult() {}

    public static ValidationResult emptyValidationResult() {
      ValidationResult vresult = new ValidationResult();
      vresult._thumbprints = new HashMap<X509Certificate, String>();
      return vresult;
    }

    public ValidationResult lock() {
      _certificates =
          Collections.unmodifiableList(new ArrayList<X509Certificate>(_thumbprints.keySet()));
      return this;
    }

    public String getCertThumbprint(X509Certificate certificate) {
      return _thumbprints.get(certificate);
    }

    public String addCertificate(X509Certificate certificate)
        throws NoSuchAlgorithmException, CertificateEncodingException {
      String thumbprint =
          DatatypeConverter.printHexBinary(
                  MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()))
              .toLowerCase();
      _thumbprints.put(certificate, thumbprint);
      return thumbprint;
    }

    public ValidationResult setValid(boolean isValid) {
      this._isValid = isValid;
      return this;
    }

    public boolean isValid() {
      return _isValid;
    }

    public List<X509Certificate> getCertificates() {
      return _certificates;
    }
  }

  private static void markIdAttributes(final Document doc, String soapNs) {

    // TODO: also handle saml assertion. Example:
    //
    // <saml:Assertion MajorVersion="1" MinorVersion="1"
    //     AssertionID="saml-0018FE864EEE1DDE86C5371CA2C53C43" Issuer="BXI/000" ...
    //
    // This will be the case in the "Sender Vouches" scenario, in which an
    // unsigned saml assertion is injected as a child of the wsse:Security element,
    // and the signature for that assertion is is embedded in wsse:Security along
    // with signatures for the timestamp and body.
    //
    // see
    // https://wiki.scn.sap.com/wiki/display/Security/Single+Sign+on+using+SAML+Sender+Vouches+example
    Consumer<NodeList> maybeMarkIdAttribute =
        (nl) -> {
          if (nl.getLength() == 1) {
            Element element = (Element) nl.item(0);
            if (element.hasAttributeNS(Namespaces.WSU, "Id")) {
              element.setIdAttributeNS(Namespaces.WSU, "Id", true);
            }
          }
        };

    // mark the Ids signed elements have an Id
    maybeMarkIdAttribute.accept(doc.getElementsByTagNameNS(soapNs, "Body"));

    NodeList nl = doc.getElementsByTagNameNS(soapNs, "Header");
    if (nl.getLength() == 1) {
      Element header = (Element) nl.item(0);
      nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
      if (nl.getLength() == 1) {
        Element security = (Element) nl.item(0);
        maybeMarkIdAttribute.accept(security.getElementsByTagNameNS(Namespaces.WSU, "Timestamp"));
        maybeMarkIdAttribute.accept(
            security.getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference"));
      }
    }
  }

  private static boolean checkCompulsoryElements(
      Document doc, String soapNs, Element signatureElement, List<String> foundTags) {
    boolean foundOne = false;
    NodeList nl = signatureElement.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
    if (nl.getLength() == 1) {
      Element signedInfo = (Element) nl.item(0);
      nl = signedInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
      if (nl.getLength() == 0) {
        return false;
      }
      for (int i = 0; i < nl.getLength(); i++) {
        Element reference = (Element) nl.item(i);
        String uri = reference.getAttribute("URI");
        Element referent = XmlUtils.getReferencedElement(doc, uri);
        if (referent != null) {
          String tagName = referent.getLocalName();
          String ns = referent.getNamespaceURI();
          if (tagName != null && ns != null) {
            if (tagName.equals("Timestamp") && ns.equals(Namespaces.WSU)) {
              // check for signature wrapping
              Node parent = referent.getParentNode();
              if (parent.getNodeType() == Node.ELEMENT_NODE &&
                  parent.getLocalName().equals("Security") &&
                  parent.getNamespaceURI().equals(Namespaces.WSSEC)) {
                Node securityParent = parent.getParentNode();
                if (securityParent.getNodeType() == Node.ELEMENT_NODE &&
                    securityParent.getLocalName().equals("Header") &&
                    securityParent.getNamespaceURI().equals(soapNs)) {
                  Node headerParent = securityParent.getParentNode();
                  if (headerParent.getNodeType() == Node.ELEMENT_NODE &&
                      headerParent.getLocalName().equals("Envelope") &&
                      headerParent.getNamespaceURI().equals(soapNs) &&
                      headerParent.getOwnerDocument().getDocumentElement().equals(headerParent)) {
                    foundTags.add("timestamp");
                    foundOne = true;
                  }
                }
              }
            }
            if (tagName.equals("Body") && ns.equals(soapNs)) {
              // check for signature wrapping
              Node parent = referent.getParentNode();
              if (parent.getNodeType() == Node.ELEMENT_NODE &&
                  parent.getLocalName().equals("Envelope") &&
                  parent.getNamespaceURI().equals(soapNs) &&
                  parent.getOwnerDocument().getDocumentElement().equals(parent)) {
                foundTags.add("body");
                foundOne = true;
              }
            }
          }
        }
      }
    }
    return foundOne;
  }

  private static void checkAlgorithms(
      Element signature, ValidateConfiguration validationConfig, MessageContext msgCtxt) {
    logger.debug("checkAlgorithms()");
    NodeList nl = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
    if (nl.getLength() == 0) throw new RuntimeException("No element: SignedInfo");

    Element signedInfo = (Element) nl.item(0);
    nl = signedInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    if (nl.getLength() == 0) throw new RuntimeException("No element: Signature/SignatureMethod");

    Element signatureMethod = (Element) nl.item(0);
    String actualSigningAlgorithm = signatureMethod.getAttribute("Algorithm");
    if (actualSigningAlgorithm == null)
      throw new RuntimeException("No attribute: SignatureMethod/@Algorithm");
    msgCtxt.setVariable(varName("signaturemethod"), actualSigningAlgorithm);

    if (validationConfig.signingMethod != null
        && !actualSigningAlgorithm.equals(validationConfig.signingMethod))
      throw new IllegalStateException("SignatureMethod/@Algorithm is not acceptable");

    if (validationConfig.digestMethod != null) {
      NodeList references = signedInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
      if (references.getLength() == 0)
        throw new RuntimeException("No element: Signature/Reference");
      for (int i = 0; i < references.getLength(); i++) {
        Element reference = (Element) references.item(i);
        NodeList digestMethodList =
            reference.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
        if (digestMethodList.getLength() == 0)
          throw new RuntimeException("No element: Signature/Reference/DigestMethod");
        Element digestMethod = (Element) digestMethodList.item(0);
        String actualDigestAlgorithm = digestMethod.getAttribute("Algorithm");
        if (!actualDigestAlgorithm.equals(validationConfig.digestMethod))
          throw new IllegalStateException("Reference/DigestMethod/@Algorithm is not acceptable");
      }
    }
  }

  private ValidationResult validate_RSA(
      Document doc, ValidateConfiguration validationConfig, MessageContext msgCtxt)
      throws MarshalException, XMLSignatureException, KeyException, CertificateExpiredException,
          CertificateNotYetValidException, NoSuchAlgorithmException, InvalidNameException,
          CertificateEncodingException {

    NodeList signatures = getSignatures(doc, validationConfig.soapNs);
    if (signatures.getLength() == 0) {
      throw new RuntimeException("No element: Signature");
    }
    ValidationResult result = ValidationResult.emptyValidationResult();
    markIdAttributes(doc, validationConfig.soapNs);

    boolean isValid = true;
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    logger.debug("Security Provider: {}", signatureFactory.getProvider().getName());

    List<String> signedElements = new ArrayList<String>();
    for (int i = 0; i < signatures.getLength(); i++) {
      if (isValid) {
        // continue to check if all prior signatures have validated
        Element signatureElement = (Element) signatures.item(i);
        logger.debug("validate_RSA() signature {}", XmlUtils.asString(signatureElement));
        checkCompulsoryElements(doc, validationConfig.soapNs, signatureElement, signedElements);
        checkAlgorithms(signatureElement, validationConfig, msgCtxt);
        NodeList keyinfoList =
            signatureElement.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
        if (keyinfoList.getLength() == 0) {
          throw new RuntimeException("No element: Signature/KeyInfo");
        }
        // TODO: cache the result of the validity check on the cert,
        // in case of multiple signatures with same cert.
        SourcedCert sourcedCert =
            getCertificate((Element) keyinfoList.item(0), doc, validationConfig.soapNs, msgCtxt);
        sourcedCert.certificate.checkValidity(); // throws if expired or not yet valid
        logger.debug("validate_RSA() cert is valid");
        if (sourcedCert.source == CertificateSource.DOCUMENT) {
          String thumbprint = result.addCertificate(sourcedCert.certificate);
          msgCtxt.setVariable(varName("cert_" + i + "_thumbprint"), thumbprint);
        }
        KeySelector ks = KeySelector.singletonKeySelector(sourcedCert.certificate.getPublicKey());
        DOMValidateContext vc = new DOMValidateContext(ks, signatureElement);
        XMLSignature signature = signatureFactory.unmarshalXMLSignature(vc);
        isValid = signature.validate(vc);
        logger.debug("validate_RSA() signature is valid? {}", isValid);
      }
    }

    // check for presence of signed elements
    if (isValid) {
      List<String> errors = new ArrayList<String>();
      if (validationConfig.requiredSignedElements.contains("timestamp")
          && !signedElements.contains("timestamp")) {
        errors.add("did not find signature for wsu:Timestamp");
      }
      if (validationConfig.requiredSignedElements.contains("body")
          && !signedElements.contains("body")) {
        errors.add("did not find signature for soap:Body");
      }
      if (errors.size() > 0) {
        isValid = false;
        msgCtxt.setVariable(varName("error"), String.join(";", errors));
      }
    }

    return result.setValid(isValid).lock();
  }

  private static Element getTimestamp(Document doc, String soapNs) {
    NodeList nl =
        getSecurityElement(doc, soapNs).getElementsByTagNameNS(Namespaces.WSU, "Timestamp");
    if (nl.getLength() == 0) {
      return null;
    }
    return (Element) nl.item(0);
  }

  private static boolean hasExpiry(Document doc, String soapNs) {
    Element timestamp = getTimestamp(doc, soapNs);
    if (timestamp == null) {
      return false;
    }
    NodeList nl = timestamp.getElementsByTagNameNS(Namespaces.WSU, "Expires");
    return (nl.getLength() > 0);
  }

  private static int getDocumentLifetime(MessageContext msgCtxt) {
    String createdString = msgCtxt.getVariable(varName("created"));
    String expiresString = msgCtxt.getVariable(varName("expiry"));
    if (createdString == null || expiresString == null) {
      return -1;
    }

    TemporalAccessor creationAccessor = DateTimeFormatter.ISO_INSTANT.parse(createdString);
    Instant created = Instant.from(creationAccessor);
    TemporalAccessor expiryAccessor = DateTimeFormatter.ISO_INSTANT.parse(expiresString);
    Instant expiry = Instant.from(expiryAccessor);
    int documentLifetime = (int) created.until(expiry, ChronoUnit.SECONDS);
    msgCtxt.setVariable(varName("lifetime"), Integer.toString(documentLifetime));
    return documentLifetime;
  }

  private static boolean isExpired(Document doc, String soapNs, MessageContext msgCtxt) {
    Element timestamp = getTimestamp(doc, soapNs);
    if (timestamp == null) {
      return false;
    }
    NodeList nl = timestamp.getElementsByTagNameNS(Namespaces.WSU, "Created");
    if (nl.getLength() == 1) {
      Element created = (Element) nl.item(0);
      String createdString = created.getTextContent();
      msgCtxt.setVariable(varName("created"), createdString);
      TemporalAccessor creationAccessor = DateTimeFormatter.ISO_INSTANT.parse(createdString);
      msgCtxt.setVariable(
          varName("created_seconds"),
          Long.toString(Instant.from(creationAccessor).getEpochSecond()));
    }

    nl = timestamp.getElementsByTagNameNS(Namespaces.WSU, "Expires");
    if (nl.getLength() == 0) {
      return false;
    }
    Element expires = (Element) nl.item(0);
    String expiryString = expires.getTextContent();
    msgCtxt.setVariable(varName("expires"), expiryString);

    TemporalAccessor expiryAccessor = DateTimeFormatter.ISO_INSTANT.parse(expiryString);
    Instant expiry = Instant.from(expiryAccessor);
    msgCtxt.setVariable(varName("expires_seconds"), Long.toString(expiry.getEpochSecond()));

    Instant now = Instant.now();
    long secondsRemaining = now.until(expiry, ChronoUnit.SECONDS);
    msgCtxt.setVariable(varName("seconds_remaining"), Long.toString(secondsRemaining));

    return (secondsRemaining <= 0L);
  }

  private boolean wantFaultOnInvalid() {
    String value = (String) this.properties.get("throw-fault-on-invalid");
    if (value == null) return true; // default true
    if (value.trim().toLowerCase().equals("false")) return false;
    return true;
  }

  private int getMaxLifetime(MessageContext msgCtxt) throws Exception {
    String lifetimeString = getSimpleOptionalProperty("max-lifetime", msgCtxt);
    if (lifetimeString == null) return 0;
    lifetimeString = lifetimeString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(lifetimeString);
    if (durationInMilliseconds < 0L) return 0;
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  private boolean requireExpiry(MessageContext msgCtxt) throws Exception {
    String requireExpiry = getSimpleOptionalProperty("require-expiry", msgCtxt);
    if (requireExpiry == null) return true;
    requireExpiry = requireExpiry.trim();
    if (requireExpiry.trim().toLowerCase().equals("false")) return false;
    return true;
  }

  private boolean wantIgnoreExpiry(MessageContext msgCtxt) throws Exception {
    String wantIgnore = getSimpleOptionalProperty("ignore-expiry", msgCtxt);
    if (wantIgnore == null) return false;
    wantIgnore = wantIgnore.trim();
    if (wantIgnore.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  private List<String> getAcceptableSubjectCommonNames(MessageContext msgCtxt) throws Exception {
    String nameList = getSimpleOptionalProperty("accept-subject-cns", msgCtxt);
    if (nameList == null) return null;
    return Arrays.asList(nameList.split(",[ ]*")).stream()
        .map(String::toLowerCase)
        .collect(Collectors.toList());
  }

  private List<String> getAcceptableThumbprints(MessageContext msgCtxt) throws Exception {
    String nameList = getSimpleRequiredProperty("accept-thumbprints", msgCtxt);
    return Arrays.asList(nameList.split(",[ ]*")).stream()
        .map(String::toLowerCase)
        .map(x -> x.replaceAll(":",""))
        .collect(Collectors.toList());
  }

  private List<String> getRequiredSignedElements(MessageContext msgCtxt) throws Exception {
    String elementList = getSimpleOptionalProperty("required-signed-elements", msgCtxt);
    if (elementList == null) elementList = "body,timestamp";

    return Arrays.asList(elementList.split(",[ ]*")).stream()
        .map(String::toLowerCase)
        .filter(c -> c.equals("body") || c.equals("timestamp"))
        .distinct()
        .collect(Collectors.toList());
  }

  static class ValidateConfiguration {
    public int maxLifetime; // optional
    public List<String> requiredSignedElements;
    public String soapNs; // optional
    public String signingMethod;
    public String digestMethod;

    public ValidateConfiguration() {}

    public ValidateConfiguration withMaxLifetime(int maxLifetime) {
      this.maxLifetime = maxLifetime;
      return this;
    }

    public ValidateConfiguration withRequiredSignedElements(List<String> requiredSignedElements) {
      this.requiredSignedElements = requiredSignedElements;
      return this;
    }

    public ValidateConfiguration withSigningMethod(String signingMethod) {
      this.signingMethod = signingMethod;
      return this;
    }

    public ValidateConfiguration withDigestMethod(String digestMethod) {
      this.digestMethod = digestMethod;
      return this;
    }

    public ValidateConfiguration withSoapNamespace(String soapNs) {
      this.soapNs = soapNs;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      msgCtxt.setVariable(varName("valid"), false);
      Document document = getDocument(msgCtxt);
      ValidateConfiguration validationConfig =
          new ValidateConfiguration()
              .withMaxLifetime(getMaxLifetime(msgCtxt))
              .withRequiredSignedElements(getRequiredSignedElements(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withSoapNamespace(
                  (getSoapVersion(msgCtxt).equals("soap1.2"))
                      ? Namespaces.SOAP1_2
                      : Namespaces.SOAP1_1);

      ValidationResult validationResult = validate_RSA(document, validationConfig, msgCtxt);
      boolean isValid = validationResult.isValid();
      if (!isValid) {
        Object previouslySetError = msgCtxt.getVariable(varName("error"));
        if (previouslySetError == null) {
          msgCtxt.setVariable(varName("error"), "signature did not verify");
        }
      }

      if (isValid && requireExpiry(msgCtxt)) {
        if (!hasExpiry(document, validationConfig.soapNs)) {
          msgCtxt.setVariable(varName("error"), "required element Timestamp/Expires is missing");
          isValid = false;
        }
      }

      if (isValid && validationConfig.maxLifetime > 0) {
        int documentLifetime = getDocumentLifetime(msgCtxt);
        if (documentLifetime < 0 || documentLifetime > validationConfig.maxLifetime) {
          msgCtxt.setVariable(
              varName("error"), "Lifetime of the document exceeds configured maximum");
          isValid = false;
        }
      }

      if (isValid) {
        boolean expired = isExpired(document, validationConfig.soapNs, msgCtxt);
        if (expired) {
          if (wantIgnoreExpiry(msgCtxt)) {
            msgCtxt.setVariable(varName("notice"), "Timestamp/Expires is past");
          } else {
            msgCtxt.setVariable(varName("error"), "Timestamp/Expires is past");
            isValid = false;
          }
        }
      }

      if (isValid) {
        // check thumbprints of certs that were embedded in the document
        List<X509Certificate> certs = validationResult.getCertificates();
        if (certs.size() > 0) {
          List<String> acceptableThumbprints = getAcceptableThumbprints(msgCtxt);
          List<String> acceptableSubjectCNs = getAcceptableSubjectCommonNames(msgCtxt);
          for (int i = 0; i < certs.size(); i++) {
            X509Certificate certificate = certs.get(i);
            String thumbprint = validationResult.getCertThumbprint(certificate);
            // msgCtxt.setVariable(varName("cert_" + i + "_thumbprint"), thumbprint);

            if (!acceptableThumbprints.contains(thumbprint)) {
              msgCtxt.setVariable(varName("error"), "certificate thumbprint not accepted");
              isValid = false;
            }

            // record issuer
            X500Principal principal = certificate.getIssuerX500Principal();
            String commonName = getCommonName(principal);
            msgCtxt.setVariable(varName("cert_" + i + "_issuer_cn"), commonName);
            // record subject
            principal = certificate.getSubjectX500Principal();
            commonName = getCommonName(principal);
            msgCtxt.setVariable(varName("cert_" + i + "_subject_cn"), commonName);
            // and check CN
            if (acceptableSubjectCNs != null && isValid) {
              if (!acceptableSubjectCNs.contains(commonName)) {
                msgCtxt.setVariable(varName("error"), "subject common name not accepted");
                isValid = false;
              }
            }
          }
        }
        msgCtxt.setVariable(varName("cert_count"), Integer.toString(certs.size()));
      }

      msgCtxt.setVariable(varName("valid"), isValid);
      if (isValid) {
        return ExecutionResult.SUCCESS;
      }
      return (wantFaultOnInvalid()) ? ExecutionResult.ABORT : ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return (wantFaultOnInvalid()) ? ExecutionResult.ABORT : ExecutionResult.SUCCESS;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return (wantFaultOnInvalid()) ? ExecutionResult.ABORT : ExecutionResult.SUCCESS;
    }
  }
}
