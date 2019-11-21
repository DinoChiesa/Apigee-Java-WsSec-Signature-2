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
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Sign extends WssecCalloutBase implements Execution {

  public Sign(Map properties) {
    super(properties);
  }

  // public static String toPrettyString(Document document, int indent) {
  //   try {
  //     // Remove whitespaces outside tags
  //     document.normalize();
  //     XPath xPath = XPathFactory.newInstance().newXPath();
  //     NodeList nodeList =
  //         (NodeList)
  //             xPath.evaluate("//text()[normalize-space()='']", document, XPathConstants.NODESET);
  //
  //     for (int i = 0; i < nodeList.getLength(); ++i) {
  //       Node node = nodeList.item(i);
  //       node.getParentNode().removeChild(node);
  //     }
  //
  //     // Setup pretty print options
  //     TransformerFactory transformerFactory = TransformerFactory.newInstance();
  //     transformerFactory.setAttribute("indent-number", indent);
  //     Transformer transformer = transformerFactory.newTransformer();
  //     transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
  //     transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
  //     transformer.setOutputProperty(OutputKeys.INDENT, "yes");
  //
  //     // Return pretty print xml string
  //     StringWriter stringWriter = new StringWriter();
  //     transformer.transform(new DOMSource(document), new StreamResult(stringWriter));
  //     return stringWriter.toString();
  //   } catch (Exception e) {
  //     throw new RuntimeException(e);
  //   }
  // }

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

  private String declareXmlnsPrefix(
      Element elt, Map<String, String> knownNamespaces, String namespaceURIToAdd) {
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

    if (elt != null) {
      elt.setAttributeNS(Namespaces.XMLNS, "xmlns:" + prefix, namespaceURIToAdd);
    }
    return prefix;
  }

  private static String getISOTimestamp(int offsetFromNow) {
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
    if (offsetFromNow != 0) zdt = zdt.plusSeconds(offsetFromNow);
    return zdt.format(DateTimeFormatter.ISO_INSTANT);
    // return ZonedDateTime.ofInstant(Instant.ofEpochSecond(secondsSinceEpoch), ZoneOffset.UTC)
    //     .format(DateTimeFormatter.ISO_INSTANT);
  }

  private String sign_RSA(Document doc, SignConfiguration signConfiguration)
      throws InstantiationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          KeyException, MarshalException, XMLSignatureException, TransformerException,
          CertificateEncodingException, InvalidNameException {
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    String soapns = Namespaces.SOAP10;

    NodeList nodes = doc.getElementsByTagNameNS(soapns, "Envelope");
    if (nodes.getLength() != 1) {
      return null;
    }
    Element envelope = (Element) nodes.item(0);

    nodes = envelope.getElementsByTagNameNS(soapns, "Body");
    if (nodes.getLength() != 1) {
      return null;
    }

    Map<String, String> knownNamespaces = Namespaces.getExistingNamespaces(envelope);
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
      // body.setIdAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", true);
      body.setIdAttributeNS(Namespaces.WSU, "Id", true);
    }

    // 2. create or get the soap:Header
    Element header = null;
    nodes = doc.getElementsByTagNameNS(soapns, "Header");
    if (nodes.getLength() == 0) {
      header = doc.createElementNS(soapns, soapPrefix + ":Header");
      envelope.insertBefore(header, body);
    } else {
      header = (Element) nodes.item(0);
    }

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
    if (signConfiguration.expiresInSeconds > 0) {
      Element expires = doc.createElementNS(Namespaces.WSU, wsuPrefix + ":Expires");
      expires.setTextContent(getISOTimestamp(signConfiguration.expiresInSeconds));
      timestamp.appendChild(expires);
    }

    // 6. maybe embed the BinarySecurityToken
    // but first, verify that the cert signs the public key that corresponds to the private key
    RSAPublicKey k1 = (RSAPublicKey) signConfiguration.certificate.getPublicKey();
    final byte[] certModulus = k1.getModulus().toByteArray();
    RSAPrivateKey k2 = (RSAPrivateKey) signConfiguration.privatekey;
    final byte[] keyModulus = k2.getModulus().toByteArray();
    String e1 = Base64.getEncoder().encodeToString(certModulus);
    String e2 = Base64.getEncoder().encodeToString(keyModulus);
    if (!e1.equals(e2)) {
      throw new KeyException(
          "public key mismatch. The public key contained in the certificate does not match the private key.");
    }

    String bstId = "none";
    if (signConfiguration.keyIdentifierType == KeyIdentifierType.BST_DIRECT_REFERENCE) {
      Element bst = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":BinarySecurityToken");
      bstId = "SecurityToken-" + java.util.UUID.randomUUID().toString();
      bst.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", bstId);
      bst.setIdAttributeNS(Namespaces.WSU, "Id", true);
      bst.setAttribute(
          "EncodingType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
      bst.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
      bst.setTextContent(
          Base64.getEncoder().encodeToString(signConfiguration.certificate.getEncoded()));
      wssecHeader.appendChild(bst);
    }

    String digestMethodUri =
        ((signConfiguration.digestMethod != null)
                && (signConfiguration.digestMethod.toLowerCase().equals("sha256")))
            ? DigestMethod.SHA256
            : DigestMethod.SHA1;

    DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

    Transform transform =
        signatureFactory.newTransform(
            "http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null);
    // Transform transform =
    //     signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);

    List<Reference> references = new ArrayList<Reference>();

    if (signConfiguration.elementsToSign == null
        || signConfiguration.elementsToSign.contains("body")) {
      references.add(
          signatureFactory.newReference(
              "#" + bodyId, digestMethod, Collections.singletonList(transform), null, null));
    }

    if (signConfiguration.elementsToSign == null
        || signConfiguration.elementsToSign.contains("timestamp")) {
      references.add(
          signatureFactory.newReference(
              "#" + timestampId, digestMethod, Collections.singletonList(transform), null, null));
    }

    // 7. add <SignatureMethod Algorithm="..."?>
    String signingMethodUri =
        ((signConfiguration.signingMethod != null)
                && (signConfiguration.signingMethod.toLowerCase().equals("rsa-sha256")))
            ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            : "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(signingMethodUri, null);

    CanonicalizationMethod canonicalizationMethod =
        signatureFactory.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);

    // The marshalled XMLSignature (SignatureS?) will be added as the last child element
    // of the specified parent node.
    DOMSignContext signingContext = new DOMSignContext(signConfiguration.privatekey, wssecHeader);
    SignedInfo signedInfo =
        signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);
    KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();

    KeyInfo keyInfo = null;
    if (signConfiguration.keyIdentifierType == KeyIdentifierType.BST_DIRECT_REFERENCE) {
      // <KeyInfo>
      //   <wssec:SecurityTokenReference>
      //     <wssec:Reference URI="#SecurityToken-e828bfab-bb52-4429"
      //
      // ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
      //   </wssec:SecurityTokenReference>
      // </KeyInfo>

      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element reference = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":Reference");
      reference.setAttribute("URI", "#" + bstId);
      reference.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
      secTokenRef.appendChild(reference);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.THUMBPRINT) {
      // <KeyInfo>
      //   <wsse:SecurityTokenReference>
      //     <wsse:KeyIdentifier
      // ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">9JscCwWHk5IvR/6JLTSayTY7M=</wsse:KeyIdentifier>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element keyId = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":KeyIdentifier");
      keyId.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1");
      keyId.setTextContent(getThumbprintBase64(signConfiguration.certificate));
      secTokenRef.appendChild(keyId);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.ISSUER_SERIAL) {
      // <KeyInfo Id="KI-2795B41DA34FD80A771574109162615124">
      //   <wsse:SecurityTokenReference wsu:Id="STR-2795B41DA34FD80A771574109162615125">
      //     <X509Data>
      //       <X509IssuerSerial>
      //         <X509IssuerName>CN=creditoexpress</X509IssuerName>
      //         <X509SerialNumber>1323432320</X509SerialNumber>
      //       </X509IssuerSerial>
      //     </X509Data>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      // String xmldsigPrefix = declareXmlnsPrefix(null, knownNamespaces, Namespaces.XMLDSIG);
      // elt.setAttributeNS(Namespaces.XMLNS, "xmlns:" + prefix, namespaceURIToAdd);
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
      Element x509IssuerSerial = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerSerial");
      Element x509IssuerName = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerName");

      if (signConfiguration.issuerNameStyle == IssuerNameStyle.SHORT) {
        x509IssuerName.setTextContent(
            "CN=" + getCommonName(signConfiguration.certificate.getSubjectX500Principal()));
      } else {
        // x509IssuerName.setTextContent(signConfiguration.certificate.getSubjectX500Principal().getName());
        x509IssuerName.setTextContent(signConfiguration.certificate.getSubjectDN().getName());
      }

      Element x509SerialNumber = doc.createElementNS(Namespaces.XMLDSIG, "X509SerialNumber");
      x509SerialNumber.setTextContent(signConfiguration.certificate.getSerialNumber().toString());

      x509IssuerSerial.appendChild(x509IssuerName);
      x509IssuerSerial.appendChild(x509SerialNumber);
      x509Data.appendChild(x509IssuerSerial);
      secTokenRef.appendChild(x509Data);

      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
      // keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
    }

    XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
    signature.sign(signingContext);

    // emit the resulting document
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(doc), new StreamResult(baos));
    return new String(baos.toByteArray(), StandardCharsets.UTF_8);
  }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        // System.out.printf("found %s\n", o.getClass().getName());
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

  private RSAPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = reformIndents(privateKeyPemString);
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    if (privateKeyPassword == null) privateKeyPassword = "";
    return readKey(privateKeyPemString, privateKeyPassword);
  }

  private int getExpiresIn(MessageContext msgCtxt) throws Exception {
    String expiryString = getSimpleOptionalProperty("expiry", msgCtxt);
    if (expiryString == null) return 0;
    expiryString = expiryString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(expiryString);
    if (durationInMilliseconds < 0L) return 0;
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  private String getSigningMethod(MessageContext msgCtxt) throws Exception {
    String signingMethod = getSimpleOptionalProperty("signing-method", msgCtxt);
    if (signingMethod == null) return null;
    signingMethod = signingMethod.trim();
    // warn on invalid values
    if (!signingMethod.toLowerCase().equals("rsa-sha1")
        && !signingMethod.toLowerCase().equals("rsa-sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for signing-method");
    }
    return signingMethod;
  }

  private String getDigestMethod(MessageContext msgCtxt) throws Exception {
    String digestMethod = getSimpleOptionalProperty("digest-method", msgCtxt);
    if (digestMethod == null) return null;
    digestMethod = digestMethod.trim();
    // warn on invalid values
    if (!digestMethod.toLowerCase().equals("sha1")
        && !digestMethod.toLowerCase().equals("sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for digest-method");
    }
    return digestMethod;
  }

  private List<String> getElementsToSign(MessageContext msgCtxt) throws Exception {
    String elementList = getSimpleOptionalProperty("elements-to-sign", msgCtxt);
    if (elementList == null) return null;
    // warn on invalid values
    List<String> toSign =
        Arrays.asList(elementList.split(",[ ]*")).stream()
            .map(String::toLowerCase)
            .filter(c -> c.equals("body") || c.equals("timestamp"))
            .distinct()
            .collect(Collectors.toList());

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

  private X509Certificate getCertificate(MessageContext msgCtxt) throws Exception {
    String certificateString = getSimpleRequiredProperty("certificate", msgCtxt);
    certificateString = certificateString.trim();
    X509Certificate certificate = (X509Certificate) certificateFromPEM(certificateString);
    X500Principal principal = certificate.getIssuerX500Principal();
    msgCtxt.setVariable(varName("cert_issuer_cn"), getCommonName(principal));
    msgCtxt.setVariable(varName("cert_thumbprint"), getThumbprintHex(certificate));
    return certificate;
  }

  enum KeyIdentifierType {
    NOT_SPECIFIED,
    THUMBPRINT,
    BST_DIRECT_REFERENCE,
    ISSUER_SERIAL
  }

  private KeyIdentifierType getKeyIdentifierType(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("key-identifier-type", msgCtxt);
    if (kitString == null) return KeyIdentifierType.BST_DIRECT_REFERENCE;
    kitString = kitString.trim().toUpperCase();
    if (kitString.equals("THUMBPRINT")) return KeyIdentifierType.THUMBPRINT;
    if (kitString.equals("BST_DIRECT_REFERENCE")) return KeyIdentifierType.BST_DIRECT_REFERENCE;
    if (kitString.equals("ISSUER_SERIAL")) return KeyIdentifierType.ISSUER_SERIAL;
    msgCtxt.setVariable(varName("warning"), "unrecognized key-identifier-type");
    return KeyIdentifierType.BST_DIRECT_REFERENCE;
  }

  enum IssuerNameStyle {
    NOT_SPECIFIED,
    SHORT,
    SUBJECT_DN
  }

  private IssuerNameStyle getIssuerNameStyle(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("issuer-name-style", msgCtxt);
    if (kitString == null) return IssuerNameStyle.SHORT;
    kitString = kitString.trim().toUpperCase();
    if (kitString.equals("SHORT")) return IssuerNameStyle.SHORT;
    if (kitString.equals("SUBJECT_DN")) return IssuerNameStyle.SUBJECT_DN;
    msgCtxt.setVariable(varName("warning"), "unrecognized issuer-name-style");
    return IssuerNameStyle.SHORT;
  }

  static class SignConfiguration {
    public RSAPrivateKey privatekey; // required
    public X509Certificate certificate; // required
    public int expiresInSeconds; // optional
    public String signingMethod;
    public String digestMethod;
    public IssuerNameStyle issuerNameStyle;
    public KeyIdentifierType keyIdentifierType;
    public List<String> elementsToSign;

    public SignConfiguration() {
      keyIdentifierType = KeyIdentifierType.BST_DIRECT_REFERENCE;
    }

    public SignConfiguration withKey(RSAPrivateKey key) {
      this.privatekey = key;
      return this;
    }

    public SignConfiguration withKeyIdentifierType(KeyIdentifierType kit) {
      this.keyIdentifierType = kit;
      return this;
    }

    public SignConfiguration withIssuerNameStyle(IssuerNameStyle ins) {
      this.issuerNameStyle = ins;
      return this;
    }

    public SignConfiguration withCertificate(X509Certificate certificate) {
      this.certificate = certificate;
      return this;
    }

    public SignConfiguration withExpiresIn(int expiresIn) {
      this.expiresInSeconds = expiresIn;
      return this;
    }

    public SignConfiguration withSigningMethod(String signingMethod) {
      this.signingMethod = signingMethod;
      return this;
    }

    public SignConfiguration withDigestMethod(String digestMethod) {
      this.digestMethod = digestMethod;
      return this;
    }

    public SignConfiguration withElementsToSign(List<String> elementsToSign) {
      this.elementsToSign = elementsToSign;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);

      SignConfiguration signConfiguration =
          new SignConfiguration()
              .withKey(getPrivateKey(msgCtxt))
              .withCertificate(getCertificate(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withIssuerNameStyle(getIssuerNameStyle(msgCtxt))
              .withExpiresIn(getExpiresIn(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withElementsToSign(getElementsToSign(msgCtxt));

      String resultingXmlString = sign_RSA(document, signConfiguration);
      String outputVar = getOutputVar(msgCtxt);
      msgCtxt.setVariable(outputVar, resultingXmlString);
      return ExecutionResult.SUCCESS;
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
