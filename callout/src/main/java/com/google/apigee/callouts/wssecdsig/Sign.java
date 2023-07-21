// Copyright 2018-2023 Google LLC
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
import com.google.apigee.xml.Constants;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
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
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
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

  java.util.concurrent.atomic.AtomicInteger counter =
      new java.util.concurrent.atomic.AtomicInteger(100);

  public Sign(Map properties) {
    super(properties);
  }

  private static String declareXmlnsPrefix(
      Element elt, Map<String, String> knownNamespaces, String namespaceURIToAdd) {
    // Search here for an existing prefix with the specified URI.
    // It is assumed that the knownNamespaces has been initialized with namespaces
    // and prefixes already defined in the document.
    String prefix = knownNamespaces.get(namespaceURIToAdd);
    if (prefix != null) {
      return prefix;
    }

    // find the default prefix for the specified URI.
    prefix = Namespaces.defaultPrefixes.get(namespaceURIToAdd);
    if (prefix == null) {
      throw new IllegalStateException(
          String.format("%s is not a well-known namespace URI", namespaceURIToAdd));
    }

    if (elt != null) {
      elt.setAttributeNS(Namespaces.XMLNS, "xmlns:" + prefix, namespaceURIToAdd);
      knownNamespaces.put(namespaceURIToAdd, prefix);
    }
    return prefix;
  }

  Map<String, String> combineMaps(Map<String, String> original, Map<String, String> toAppend) {
    for (String key : toAppend.keySet()) {
      if (!original.containsKey(key)) {
        original.put(key, toAppend.get(key));
      }
    }
    return original;
  }

  Map<String, String> transposeMap(Map<String, String> input) {
    Map<String, String> output = new HashMap<String, String>();
    for (String key : input.keySet()) {
      String value = input.get(key);
      output.put(value, key);
    }
    return output;
  }

  private /* static */ String randomId() {
    return String.valueOf(counter.getAndIncrement());
    // return java.util.UUID.randomUUID().toString().replaceAll("[-]", "");
  }

  private static String getISOTimestamp(int offsetFromNow) {
    ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
    if (offsetFromNow != 0) zdt = zdt.plusSeconds(offsetFromNow);
    return zdt.format(DateTimeFormatter.ISO_INSTANT);
    // return ZonedDateTime.ofInstant(Instant.ofEpochSecond(secondsSinceEpoch), ZoneOffset.UTC)
    //     .format(DateTimeFormatter.ISO_INSTANT);
  }

  private String sign_RSA(Document doc, SignConfiguration signConfiguration)
      throws InstantiationException,
          NoSuchAlgorithmException,
          InvalidAlgorithmParameterException,
          KeyException,
          MarshalException,
          XMLSignatureException,
          TransformerException,
          CertificateEncodingException,
          InvalidNameException {
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

    String soapns =
        (signConfiguration.soapVersion.equals("soap1.2")) ? Namespaces.SOAP1_2 : Namespaces.SOAP1_1;

    NodeList nodes = doc.getElementsByTagNameNS(soapns, "Envelope");
    if (nodes.getLength() != 1) {
      throw new IllegalStateException("No soap:Envelope found");
    }
    Element envelope = (Element) nodes.item(0);

    nodes = envelope.getElementsByTagNameNS(soapns, "Body");
    if (nodes.getLength() != 1) {
      throw new IllegalStateException("No soap:Body found");
    }

    Map<String, String> knownNamespacesAtRoot = Namespaces.getExistingNamespaces(envelope);
    String wsuPrefix = declareXmlnsPrefix(envelope, knownNamespacesAtRoot, Namespaces.WSU);
    String soapPrefix = declareXmlnsPrefix(envelope, knownNamespacesAtRoot, soapns);

    BiFunction<Element, String, String> wsuIdInjector =
        (elt, prefix) -> {
          String id = prefix + "-" + randomId();
          elt.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", id);
          elt.setIdAttributeNS(Namespaces.WSU, "Id", true);
          return id;
        };

    Function<String, String> dsPrefix =
        localName -> {
          return (signConfiguration.digSigPrefix != null)
              ? signConfiguration.digSigPrefix + ":" + localName
              : localName;
        };

    // 1. get or set the Id of the Body element
    Element body = (Element) nodes.item(0);

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
    String wssePrefix = null;

    nodes = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nodes.getLength() == 0) {
      String knownWssePrefix = knownNamespacesAtRoot.get(Namespaces.WSSEC);
      wssePrefix =
          (knownWssePrefix != null)
              ? knownWssePrefix
              : Namespaces.defaultPrefixes.get(Namespaces.WSSEC);
      wssecHeader = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":Security");
      wssecHeader.setAttributeNS(soapns, soapPrefix + ":mustUnderstand", "1");
      if (knownWssePrefix == null) {
        wssecHeader.setAttributeNS(Namespaces.XMLNS, "xmlns:" + wssePrefix, Namespaces.WSSEC);
      }
      header.appendChild(wssecHeader);
    } else {
      wssecHeader = (Element) nodes.item(0);
      if (!wssecHeader.hasAttributeNS(soapns, "mustUnderstand")) {
        wssecHeader.setAttributeNS(soapns, soapPrefix + ":mustUnderstand", "1");
      }
      wssePrefix = declareXmlnsPrefix(wssecHeader, knownNamespacesAtRoot, Namespaces.WSSEC);
    }

    // 4. embed a Timestamp element under the wssecHeader element (always)
    Element timestamp = doc.createElementNS(Namespaces.WSU, wsuPrefix + ":Timestamp");
    wsuIdInjector.apply(timestamp, "TS");
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

    // 6. for each desired SignatureConfirmation, get or embed an element with a distinct Id
    List<String> sigConfirmationIds = null;
    if (signConfiguration.confirmations != null) {
      sigConfirmationIds = new ArrayList<String>();
      Map<String, String> knownNsAtSecurity = Namespaces.getExistingNamespaces(wssecHeader);
      String wsse11Prefix = declareXmlnsPrefix(wssecHeader, knownNsAtSecurity, Namespaces.WSSEC_11);
      NodeList existingConfirmations =
          wssecHeader.getElementsByTagNameNS(Namespaces.WSSEC_11, "SignatureConfirmation");
      int numExistingConfirmations = existingConfirmations.getLength();
      if (signConfiguration.confirmations.size() == 1
          && signConfiguration.confirmations.get(0).equals("*all*")) {
        // sign them all
        for (int i = 0; i < numExistingConfirmations; i++) {
          Element confirmation = (Element) existingConfirmations.item(i);
          sigConfirmationIds.add(
              (confirmation.hasAttributeNS(Namespaces.WSU, "Id"))
                  ? confirmation.getAttributeNS(Namespaces.WSU, "Id")
                  : wsuIdInjector.apply(confirmation, "Conf"));
        }
      } else {
        for (String value : signConfiguration.confirmations) {
          // find existing SignatureConfirmation element with that value, or inject one
          Element foundMatch = null;
          for (int i = 0; i < numExistingConfirmations && foundMatch == null; i++) {
            Element confirmation = (Element) nodes.item(i);
            if (confirmation.hasAttribute("Value")
                && value.equals(confirmation.getAttribute("Value"))) {
              foundMatch = confirmation;
            }
          }
          if (foundMatch != null) {
            sigConfirmationIds.add(
                (foundMatch.hasAttributeNS(Namespaces.WSU, "Id"))
                    ? foundMatch.getAttributeNS(Namespaces.WSU, "Id")
                    : wsuIdInjector.apply(foundMatch, "Conf"));
          } else {
            // inject a SignatureConfirmation element for the specified value
            Element confirmation =
                doc.createElementNS(Namespaces.WSSEC_11, wsse11Prefix + ":SignatureConfirmation");
            if (!value.equals("")) {
              // There is a special case of no Value attr at all.
              confirmation.setAttribute("Value", value);
            }
            sigConfirmationIds.add(wsuIdInjector.apply(confirmation, "Conf"));
            wssecHeader.appendChild(confirmation);
          }
        }
      }
    }

    // 7. maybe embed the BinarySecurityToken
    // but first, verify that the cert signs the public key that corresponds to the private key
    RSAPublicKey certPublicKey = (RSAPublicKey) signConfiguration.certificate.getPublicKey();
    final byte[] certModulus = certPublicKey.getModulus().toByteArray();
    RSAPrivateKey configPrivateKey = (RSAPrivateKey) signConfiguration.privatekey;
    final byte[] keyModulus = configPrivateKey.getModulus().toByteArray();
    String encodedCertModulus = Base64.getEncoder().encodeToString(certModulus);
    String encodedKeyModulus = Base64.getEncoder().encodeToString(keyModulus);
    if (!encodedCertModulus.equals(encodedKeyModulus)) {
      throw new KeyException(
          "public key mismatch. The public key contained in the certificate does not match the"
              + " private key.");
    }

    String bstId = "none";
    if (signConfiguration.keyIdentifierType == KeyIdentifierType.BST_DIRECT_REFERENCE) {
      Element bst = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":BinarySecurityToken");
      bstId = wsuIdInjector.apply(bst, "ST");
      bst.setAttribute("EncodingType", Constants.BASE64_BINARY);
      bst.setAttribute("ValueType", Constants.X509_V3_TYPE);
      bst.setTextContent(
          Base64.getEncoder().encodeToString(signConfiguration.certificate.getEncoded()));
      wssecHeader.appendChild(bst);
    }

    // 8. specify the things to be signed, and how
    TransformParameterSpec tps =
        (signConfiguration.transformInclusiveNamespaces != null)
            ? new ExcC14NParameterSpec(
                signConfiguration.transformInclusiveNamespaces.stream()
                    .map(s -> knownNamespacesAtRoot.get(s))
                    .filter(s -> s != null)
                    .collect(Collectors.toList()))
            : null;

    // always this transform
    Transform transform =
        signatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", tps);

    // Transform transform =
    //     signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);

    // set the digest method
    String digestMethodUri =
        (signConfiguration.digestMethod != null)
            ? signConfiguration.digestMethod
            : DigestMethod.SHA1;
    DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

    // add signature references.
    List<Reference> references = new ArrayList<Reference>();

    // allow signing of any element specified by prefix:Element
    Map<String, String> availablePrefixes =
        combineMaps(transposeMap(knownNamespacesAtRoot), Namespaces.defaultNamespaces);
    if (signConfiguration.elementsToSign == null) {
      signConfiguration.elementsToSign =
          Arrays.asList(Namespaces.defaultPrefixes.get(soapns) + ":Body", "wsu:Timestamp");
    }
    signConfiguration.elementsToSign.forEach(
        qualifiedTag -> {
          String ns = "";
          String unqualifiedTag = null;
          if (qualifiedTag.indexOf(":") > 0) {
            String[] parts = qualifiedTag.split(":", 2);
            ns = availablePrefixes.get(parts[0]);
            if (ns == null) {
              throw new IllegalStateException(
                  String.format(
                      "unrecognized namespace prefix. The prefix must be one of {%s}",
                      String.join(",", availablePrefixes.keySet())));
            }
            unqualifiedTag = parts[1];
          } else {
            unqualifiedTag = qualifiedTag;
          }

          NodeList nl = doc.getElementsByTagNameNS(ns, unqualifiedTag);
          if (nl.getLength() != 1) {
            throw new IllegalStateException(String.format("No %s found to sign", qualifiedTag));
          }
          Element element = (Element) nl.item(0);

          String elementId =
              (element.hasAttributeNS(Namespaces.WSU, "Id"))
                  ? element.getAttributeNS(Namespaces.WSU, "Id")
                  : wsuIdInjector.apply(element, unqualifiedTag);

          references.add(
              signatureFactory.newReference(
                  "#" + elementId, digestMethod, Collections.singletonList(transform), null, null));
        });

    // now any SignatureConfirmation elements
    if (sigConfirmationIds != null) {
      for (String confirmationId : sigConfirmationIds) {
        references.add(
            signatureFactory.newReference(
                "#" + confirmationId,
                digestMethod,
                Collections.singletonList(transform),
                null,
                null));
      }
    }

    // 9. add <SignatureMethod Algorithm="..."?>
    String signingMethodUri =
        (signConfiguration.signingMethod != null)
            ? signConfiguration.signingMethod
            : Constants.SIGNING_METHOD_RSA_SHA1;
    SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(signingMethodUri, null);

    C14NMethodParameterSpec c14nParamSpec = null;
    if (signConfiguration.c14nInclusiveNamespaces != null) {
      // <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
      //   <ec:InclusiveNamespaces
      //                xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
      //                PrefixList="ns1 ns2"/>
      // </ds:CanonicalizationMethod>

      List<String> prefixes =
          signConfiguration.c14nInclusiveNamespaces.stream()
              .map(s -> knownNamespacesAtRoot.get(s))
              .filter(s -> s != null)
              .collect(Collectors.toList());

      c14nParamSpec = new ExcC14NParameterSpec(prefixes);
    }

    CanonicalizationMethod canonicalizationMethod =
        signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, c14nParamSpec);

    // The marshalled XMLSignature (SignatureS?) will be added as the last child element
    // of the specified parent node.
    DOMSignContext signingContext = new DOMSignContext(signConfiguration.privatekey, wssecHeader);
    if (signConfiguration.digSigPrefix != null) {
      signingContext.setDefaultNamespacePrefix(signConfiguration.digSigPrefix);
    }
    signingContext.putNamespacePrefix("http://www.w3.org/2001/10/xml-exc-c14n#", "ec");

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
      reference.setAttribute("ValueType", Constants.X509_V3_TYPE);
      secTokenRef.appendChild(reference);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.THUMBPRINT) {
      // <KeyInfo>
      //   <wsse:SecurityTokenReference>
      //     <wsse:KeyIdentifier
      //
      // ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">9JscCwWHk5IvR/6JLTSayTY7M=</wsse:KeyIdentifier>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element keyId = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":KeyIdentifier");
      keyId.setAttribute("ValueType", Constants.THUMBPRINT_SHA1);

      keyId.setTextContent(getThumbprintBase64(signConfiguration.certificate));
      secTokenRef.appendChild(keyId);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT) {
      // <KeyInfo>
      //   <X509Data>
      //
      // <X509Certificate>MIICAjCCAWugAwIBAgIQwZyW5YOCXZxHg1MBV2CpvDANBgkhkiG9w0BAQnEdD9tI7IYAAoK4O+35EOzcXbvc4Kzz7BQnulQ=</X509Certificate>
      //   </X509Data>
      // </KeyInfo>
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509Data"));
      Element x509Certificate =
          doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509Certificate"));
      x509Certificate.setTextContent(
          Base64.getEncoder().encodeToString(signConfiguration.certificate.getEncoded()));
      x509Data.appendChild(x509Certificate);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(x509Data);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.RSA_KEY_VALUE) {
      // <KeyInfo>
      //   <KeyValue>
      //     <RSAKeyValue>
      //       <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
      //       <Exponent>AQAB</Exponent>
      //     </RSAKeyValue>
      //   </KeyValue>
      // </KeyInfo>
      Element keyValue = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("KeyValue"));
      Element rsaKeyValue = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("RSAKeyValue"));
      Element modulus = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("Modulus"));
      Element exponent = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("Exponent"));
      modulus.setTextContent(encodedCertModulus);
      final byte[] certExponent = certPublicKey.getPublicExponent().toByteArray();
      String encodedCertExponent = Base64.getEncoder().encodeToString(certExponent);
      exponent.setTextContent(encodedCertExponent);
      rsaKeyValue.appendChild(modulus);
      rsaKeyValue.appendChild(exponent);
      keyValue.appendChild(rsaKeyValue);
      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(keyValue);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
    } else if (signConfiguration.keyIdentifierType == KeyIdentifierType.ISSUER_SERIAL) {
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
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      wsuIdInjector.apply(secTokenRef, "STR");
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509Data"));
      Element x509IssuerSerial =
          doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509IssuerSerial"));
      Element x509IssuerName =
          doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509IssuerName"));

      if (signConfiguration.issuerNameStyle == IssuerNameStyle.CN) {
        x509IssuerName.setTextContent(
            "CN=" + getCommonName(signConfiguration.certificate.getIssuerDN().getName()));
      } else {
        // x509IssuerName.setTextContent(signConfiguration.certificate.getSubjectX500Principal().getName());
        x509IssuerName.setTextContent(signConfiguration.certificate.getIssuerDN().getName());
      }

      Element x509SerialNumber =
          doc.createElementNS(Namespaces.XMLDSIG, dsPrefix.apply("X509SerialNumber"));
      x509SerialNumber.setTextContent(signConfiguration.certificate.getSerialNumber().toString());

      x509IssuerSerial.appendChild(x509IssuerName);
      x509IssuerSerial.appendChild(x509SerialNumber);
      x509Data.appendChild(x509IssuerSerial);
      secTokenRef.appendChild(x509Data);

      javax.xml.crypto.XMLStructure structure = new javax.xml.crypto.dom.DOMStructure(secTokenRef);
      keyInfo = kif.newKeyInfo(java.util.Collections.singletonList(structure));
      // keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
    }

    // 9. sign
    XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
    signature.sign(signingContext);

    // 10. emit the resulting document
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(doc), new StreamResult(baos));
    return new String(baos.toByteArray(), StandardCharsets.UTF_8);
  }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException,
          OperatorCreationException,
          PKCSException,
          InvalidKeySpecException,
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

  private List<String> getElementsToSign(MessageContext msgCtxt) throws Exception {
    String elementList = getSimpleOptionalProperty("elements-to-sign", msgCtxt);
    // if (elementList == null) elementList = "soap:Body, wsu:Timestamp";
    if (elementList == null) return null; // will default later

    return Arrays.asList(elementList.split(",[ ]*")).stream()
        .distinct()
        .collect(Collectors.toList());
  }

  private List<String> getConfirmations(MessageContext msgCtxt) throws Exception {
    String value = (String) this.properties.get("confirmations");
    if (value == null) {
      return null;
    }
    value = value.trim();
    if (value.equals("")) {
      return Arrays.asList(""); // one blank element. Indicates no signature on initiator.
    }
    value = resolvePropertyValue(value, msgCtxt);
    if (value == null || value.equals("")) {
      return null;
    }

    // normalize
    List<String> confirmationValues = Arrays.asList(value.split(",[ ]*"));
    return confirmationValues;
  }

  private List<String> getInclusiveNamespaces(String label, MessageContext msgCtxt)
      throws Exception {
    String nsList = getSimpleOptionalProperty(label, msgCtxt);
    if (nsList == null) return null;
    List<String> namespaces =
        Arrays.asList(nsList.split(",[ ]*")).stream().distinct().collect(Collectors.toList());
    return namespaces;
  }

  private List<String> getC14nInclusiveNamespaces(MessageContext msgCtxt) throws Exception {
    return getInclusiveNamespaces("c14n-inclusive-namespaces", msgCtxt);
  }

  private List<String> getTransformInclusiveNamespaces(MessageContext msgCtxt) throws Exception {
    return getInclusiveNamespaces("transform-inclusive-namespaces", msgCtxt);
  }

  private String getDigSigPrefix(MessageContext msgCtxt) throws Exception {
    String dsPrefix = getSimpleOptionalProperty("ds-prefix", msgCtxt);
    return dsPrefix;
  }

  enum KeyIdentifierType {
    NOT_SPECIFIED,
    THUMBPRINT,
    X509_CERT_DIRECT,
    BST_DIRECT_REFERENCE,
    RSA_KEY_VALUE,
    ISSUER_SERIAL;

    static KeyIdentifierType fromString(String s) {
      for (KeyIdentifierType t : KeyIdentifierType.values()) {
        if (t.name().equals(s)) return t;
      }
      return KeyIdentifierType.NOT_SPECIFIED;
    }
  }

  private KeyIdentifierType getKeyIdentifierType(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("key-identifier-type", msgCtxt);
    if (kitString == null) return KeyIdentifierType.BST_DIRECT_REFERENCE;
    kitString = kitString.trim().toUpperCase();
    KeyIdentifierType t = KeyIdentifierType.fromString(kitString);
    if (t == KeyIdentifierType.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized key-identifier-type");
      return KeyIdentifierType.BST_DIRECT_REFERENCE;
    }
    return t;
  }

  static class SignConfiguration {
    public RSAPrivateKey privatekey; // required
    public X509Certificate certificate; // required
    public int expiresInSeconds; // optional
    public String soapVersion; // optional
    public String signingMethod;
    public String digestMethod;
    public IssuerNameStyle issuerNameStyle;
    public KeyIdentifierType keyIdentifierType;
    public List<String> elementsToSign;
    public List<String> confirmations = null;
    public List<String> c14nInclusiveNamespaces;
    public List<String> transformInclusiveNamespaces;
    public String digSigPrefix;

    public SignConfiguration() {
      keyIdentifierType = KeyIdentifierType.BST_DIRECT_REFERENCE;
    }

    public SignConfiguration withSoapVersion(String version) {
      this.soapVersion = version;
      return this;
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

    public SignConfiguration withConfirmations(List<String> confirmations) {
      this.confirmations = confirmations;
      return this;
    }

    public SignConfiguration withC14nInclusiveNamespaces(List<String> inclusiveNamespaces) {
      this.c14nInclusiveNamespaces = inclusiveNamespaces;
      return this;
    }

    public SignConfiguration withTransformInclusiveNamespaces(List<String> inclusiveNamespaces) {
      this.transformInclusiveNamespaces = inclusiveNamespaces;
      return this;
    }

    public SignConfiguration withDigSigPrefix(String prefix) {
      this.digSigPrefix = prefix;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);

      SignConfiguration signConfiguration =
          new SignConfiguration()
              .withSoapVersion(getSoapVersion(msgCtxt))
              .withKey(getPrivateKey(msgCtxt))
              .withCertificate(getCertificateFromConfiguration(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withIssuerNameStyle(getIssuerNameStyle(msgCtxt))
              .withExpiresIn(getExpiresIn(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withElementsToSign(getElementsToSign(msgCtxt))
              .withConfirmations(getConfirmations(msgCtxt))
              .withC14nInclusiveNamespaces(getC14nInclusiveNamespaces(msgCtxt))
              .withTransformInclusiveNamespaces(getTransformInclusiveNamespaces(msgCtxt))
              .withDigSigPrefix(getDigSigPrefix(msgCtxt));

      String resultingXmlString = sign_RSA(document, signConfiguration);
      String outputVar = getOutputVar(msgCtxt);
      msgCtxt.setVariable(outputVar, resultingXmlString);
      return ExecutionResult.SUCCESS;
    } catch (org.xml.sax.SAXParseException saxpe) {
      // bad input document
      setExceptionVariables(saxpe, msgCtxt);
      return ExecutionResult.ABORT;
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
